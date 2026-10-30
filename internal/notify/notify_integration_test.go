//go:build integration

package notify

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

// receiver records verified notifications, or answers fail when set.
type receiver struct {
	mu     sync.Mutex
	got    []map[string]any
	fail   bool
	secret []byte
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	body, _ := io.ReadAll(req.Body)
	if r.fail || req.Header.Get("X-Ligo-Signature") != Sign(r.secret, req.Header.Get("X-Ligo-Timestamp"), body) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var v map[string]any
	_ = json.Unmarshal(body, &v)
	r.got = append(r.got, v)
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

// TestDelivery: rows written in the event's transaction for the webhooks
// that want it are delivered once, signed, verified against the webhook's
// CA; a failing receiver is retried with backoff and abandoned after 24h
// (AC-37); old rows are purged.
func TestDelivery(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), os.Getenv("CI") != "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	x := uuid.NewV7().String()[24:]
	oncall, dba := "oncall-"+x, "dba-"+x
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), "delete from notification_outbox where webhook in ($1, $2)", oncall, dba)
	})

	rec := &receiver{secret: []byte("s3cret")}
	srv := httptest.NewTLSServer(rec)
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	t.Setenv("LIGO_TEST_HOOK_SECRET", "s3cret")
	hooks := []config.Webhook{
		{Name: oncall, URL: srv.URL, CACertFile: ca, HMACSecretEnv: "LIGO_TEST_HOOK_SECRET", Events: []string{"BREAK_GLASS_USED", "CR_AWAITING_APPROVAL"}},
		{Name: dba, URL: srv.URL, CACertFile: ca, HMACSecretEnv: "LIGO_TEST_HOOK_SECRET", Events: []string{"CR_AWAITING_APPROVAL"}, Scopes: []string{"dc/corp-prod/*"}},
	}
	outbox := &Outbox{Webhooks: hooks}
	err = pgx.BeginFunc(ctx, pools.App, func(tx pgx.Tx) error {
		for _, e := range []Event{
			{Name: "BREAK_GLASS_USED", Scopes: []string{"dc/corp-prod"}, Payload: map[string]any{"actor": "livia", "zone": "prod"}},
			{Name: "CR_AWAITING_APPROVAL", Scopes: []string{"cloud/fin-01/payments"}, Payload: map[string]any{"side": "SOURCE"}},
			{Name: "SYSTEM_MAINTENANCE_ENABLED"}, // nobody subscribes
		} {
			if err := outbox.Enqueue(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := owner.QueryRow(ctx, "select count(*) from notification_outbox where webhook in ($1, $2)", oncall, dba).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("outbox rows %d (%v), want 2: the dba webhook filters cloud scopes", rows, err)
	}
	d, err := NewDispatcher(pools.App, hooks, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if ran, err := d.Dispatch(ctx); !ran || err != nil || rec.count() != 2 {
		t.Fatalf("dispatch: %v %v, %d delivered", ran, err, rec.count())
	}
	if rec.got[0]["eventId"] == "" || rec.got[0]["event"] != "BREAK_GLASS_USED" || rec.got[0]["actor"] != "livia" || rec.got[0]["occurredAt"] == nil {
		t.Errorf("payload: %v", rec.got[0])
	}
	if _, err := d.Dispatch(ctx); err != nil || rec.count() != 2 {
		t.Errorf("delivered twice: %d", rec.count())
	}

	// AC-37: the receiver is down; the change committed anyway, delivery is retried, then abandoned after 24h
	rec.fail = true
	if err := pgx.BeginFunc(ctx, pools.App, func(tx pgx.Tx) error {
		return outbox.Enqueue(ctx, tx, Event{Name: "BREAK_GLASS_USED", Payload: map[string]any{"actor": "livia"}})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	var attempts int
	var lastError string
	var wait time.Duration
	if err := owner.QueryRow(ctx, `select attempts, last_error, extract(epoch from next_attempt_at - now())::int * interval '1 second'
		from notification_outbox where webhook = $1 and delivered_at is null`, oncall).Scan(&attempts, &lastError, &wait); err != nil ||
		attempts != 1 || wait < 5*time.Second || wait > 10*time.Second {
		t.Fatalf("retry: %d attempts, %q, next in %v (%v)", attempts, lastError, wait, err)
	}
	if _, err := owner.Exec(ctx, `update notification_outbox set created_at = now() - interval '25 hours', next_attempt_at = now()
		where webhook = $1 and delivered_at is null`, oncall); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	var abandoned bool
	if err := owner.QueryRow(ctx, "select abandoned_at is not null from notification_outbox where webhook = $1 and delivered_at is null", oncall).
		Scan(&abandoned); err != nil || !abandoned {
		t.Errorf("not abandoned after 24h (%v)", err)
	}

	// rows delivered or abandoned 30 days ago are purged; a webhook no longer configured is an error
	if _, err := owner.Exec(ctx, "update notification_outbox set delivered_at = now() - interval '31 days' where webhook = $1 and delivered_at is not null", oncall); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(ctx, pools.App, func(tx pgx.Tx) error {
		return outbox.Enqueue(ctx, tx, Event{Name: "CR_AWAITING_APPROVAL", Scopes: []string{"dc/corp-prod/ledger"}})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Dispatcher{DB: pools.App, Logger: slog.New(slog.DiscardHandler)}).Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, "select count(*) from notification_outbox where webhook = $1 and delivered_at is not null", oncall).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("%d delivered rows left (%v)", rows, err)
	}
	if err := owner.QueryRow(ctx, "select last_error from notification_outbox where webhook = $1 and delivered_at is null and abandoned_at is null", dba).
		Scan(&lastError); err != nil || lastError != "webhook "+dba+" is no longer configured" {
		t.Errorf("an unknown webhook: %q (%v)", lastError, err)
	}
	if _, err := NewDispatcher(pools.App, []config.Webhook{{Name: "x", HMACSecretEnv: "LIGO_TEST_UNSET_SECRET"}}, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a webhook without its secret")
	}
	if _, err := NewDispatcher(pools.App, []config.Webhook{{Name: "x", HMACSecretEnv: "LIGO_TEST_HOOK_SECRET", CACertFile: filepath.Join(t.TempDir(), "none")}}, nil); err == nil {
		t.Error("a webhook without its CA file")
	}
}
