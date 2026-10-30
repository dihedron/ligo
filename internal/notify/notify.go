// Package notify announces events to webhooks (§7.5): a transactional
// outbox, filled in the event's own transaction, and a singleton dispatcher
// that delivers it with HMAC signatures, at least once, never blocking the
// change it announces.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event is something to announce: its name (§7.5 "Events"), the scopes a
// webhook's scope filter is matched against, and the fields of its payload
// beyond eventId, event and occurredAt. Payloads hold no secrets.
type Event struct {
	Name    string
	Scopes  []string
	Payload map[string]any
}

// global reports whether name is delivered regardless of scope filters:
// configuration and system events.
func global(name string) bool {
	return strings.HasPrefix(name, "CONFIG_") || strings.HasPrefix(name, "SYSTEM_")
}

// Outbox writes events for the webhooks that subscribe to them.
type Outbox struct {
	Webhooks []config.Webhook
}

// wants reports whether w receives e: it subscribes to it and, unless the
// event is global, a scope of the event matches its filter.
func wants(w config.Webhook, e Event) bool {
	if !slices.Contains(w.Events, e.Name) {
		return false
	}
	if global(e.Name) || len(w.Scopes) == 0 {
		return true
	}
	return slices.ContainsFunc(w.Scopes, func(p string) bool {
		return slices.ContainsFunc(e.Scopes, func(s string) bool { return governance.ScopeMatches(p, s) })
	})
}

// Enqueue inserts a row per webhook that receives e, in tx: the event's
// transaction, before its audit entry (§4.3 lock order).
func (o *Outbox) Enqueue(ctx context.Context, tx pgx.Tx, e Event) error {
	if o == nil {
		return nil
	}
	for _, w := range o.Webhooks {
		if !wants(w, e) {
			continue
		}
		id := uuid.NewV7()
		payload := maps.Clone(e.Payload)
		if payload == nil {
			payload = map[string]any{}
		}
		payload["eventId"], payload["event"], payload["occurredAt"] = id.String(), e.Name, time.Now().UTC().Format(time.RFC3339)
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO notification_outbox (event_id, webhook, event, payload) VALUES ($1, $2, $3, $4)",
			id, w.Name, e.Name, data); err != nil {
			return fmt.Errorf("notify: outbox: %w", err)
		}
	}
	return nil
}

// Retention: a row is abandoned this long after it was written, and
// delivered or abandoned rows are purged after purgeAfter (§7.5, §6.3).
const (
	abandonAfter = 24 * time.Hour
	purgeAfter   = 30 * 24 * time.Hour
)

// backoff is the wait after the n-th failed attempt: 10s doubling to 15m.
func backoff(n int) time.Duration {
	d := 10 * time.Second
	for i := 1; i < n && d < 15*time.Minute; i++ {
		d *= 2
	}
	return min(d, 15*time.Minute)
}

// Sign is the X-Ligo-Signature of body sent at timestamp (§7.5
// "Authenticity").
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// target is a webhook ready to receive.
type target struct {
	url    string
	secret []byte
	client *http.Client
}

// Dispatcher delivers the outbox.
type Dispatcher struct {
	DB       *pgxpool.Pool // the app pool
	Interval time.Duration // between passes; default 5s
	Logger   *slog.Logger
	targets  map[string]target
}

// NewDispatcher prepares the configured webhooks: their secrets from the
// environment, their CA bundles and timeouts (default 10s).
func NewDispatcher(db *pgxpool.Pool, webhooks []config.Webhook, logger *slog.Logger) (*Dispatcher, error) {
	d := &Dispatcher{DB: db, Logger: logger, targets: map[string]target{}}
	for _, w := range webhooks {
		secret := os.Getenv(w.HMACSecretEnv)
		if secret == "" {
			return nil, fmt.Errorf("notify: webhook %s: environment variable %q is not set", w.Name, w.HMACSecretEnv)
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if w.CACertFile != "" {
			pem, err := os.ReadFile(w.CACertFile)
			if err != nil {
				return nil, fmt.Errorf("notify: webhook %s: ca_cert_file: %w", w.Name, err)
			}
			cfg.RootCAs = x509.NewCertPool()
			if !cfg.RootCAs.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("notify: webhook %s: ca_cert_file %s: no certificate", w.Name, w.CACertFile)
			}
		}
		timeout := w.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		d.targets[w.Name] = target{url: w.URL, secret: []byte(secret),
			client: &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: cfg}}}
	}
	return d, nil
}

// Run dispatches every Interval until ctx ends; errors wait for the next
// tick.
func (d *Dispatcher) Run(ctx context.Context) {
	interval := d.Interval
	if interval == 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := d.Dispatch(ctx); err != nil {
				d.Logger.Error("notifications", "error", err)
			}
		}
	}
}

// Dispatch delivers the due rows if this replica takes the lock
// ligo_notifier, and purges old ones; it reports whether it ran.
func (d *Dispatcher) Dispatch(ctx context.Context) (bool, error) {
	conn, err := d.DB.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext('ligo_notifier'))").Scan(&locked); err != nil || !locked {
		return false, err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext('ligo_notifier'))") }()
	rows, err := d.DB.Query(ctx, `SELECT id, webhook, payload, attempts, created_at < now() - $1::interval FROM notification_outbox
		WHERE delivered_at IS NULL AND abandoned_at IS NULL AND next_attempt_at <= now() ORDER BY id LIMIT 100`, abandonAfter.String())
	if err != nil {
		return true, err
	}
	type due struct {
		id       int64
		webhook  string
		payload  []byte
		attempts int
		old      bool
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (due, error) {
		var x due
		return x, r.Scan(&x.id, &x.webhook, &x.payload, &x.attempts, &x.old)
	})
	if err != nil {
		return true, err
	}
	var errs []error
	for _, x := range list {
		derr := d.deliver(ctx, x.webhook, x.payload)
		var q string
		var args []any
		switch {
		case derr == nil:
			q, args = "UPDATE notification_outbox SET delivered_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = $1", []any{x.id}
		case x.old:
			d.Logger.Error("notification abandoned", "webhook", x.webhook, "outbox_id", x.id, "attempts", x.attempts+1, "error", derr)
			q, args = "UPDATE notification_outbox SET abandoned_at = now(), attempts = attempts + 1, last_error = $2 WHERE id = $1",
				[]any{x.id, limit(derr.Error())}
		default:
			q, args = "UPDATE notification_outbox SET attempts = attempts + 1, last_error = $2, next_attempt_at = now() + $3::interval WHERE id = $1",
				[]any{x.id, limit(derr.Error()), backoff(x.attempts + 1).String()}
		}
		if _, err := d.DB.Exec(ctx, q, args...); err != nil {
			errs = append(errs, err)
		}
	}
	if _, err := d.DB.Exec(ctx, `DELETE FROM notification_outbox
		WHERE coalesce(delivered_at, abandoned_at) < now() - $1::interval`, purgeAfter.String()); err != nil {
		errs = append(errs, err)
	}
	return true, errors.Join(errs...)
}

// deliver POSTs one payload, signed; any 2xx answer is a delivery.
func (d *Dispatcher) deliver(ctx context.Context, webhook string, payload []byte) error {
	t, ok := d.targets[webhook]
	if !ok {
		return fmt.Errorf("webhook %s is no longer configured", webhook)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ligo-Timestamp", ts)
	req.Header.Set("X-Ligo-Signature", Sign(t.secret, ts, payload))
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook %s answered %s", webhook, resp.Status)
	}
	return nil
}

// limit fits an error into last_error.
func limit(s string) string {
	if len(s) > 1024 {
		return s[:1024]
	}
	return s
}
