// Package resolution keeps the in-process cache that resolves a workload's
// SPIFFE ID to the bindings it receives (§4.5, INV-01, INV-15, INV-25).
package resolution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ErrStale means that the cache has not been refreshed for max_staleness:
// the workload API answers 503 (fail closed, §4.5 rule 4).
var ErrStale = errors.New("resolution cache is stale")

// channel is the NOTIFY channel of the bindings_notify and sources_notify
// triggers (§4.2).
const channel = "ligo_bindings_changed"

const viewColumns = `id, name, platform_type, platform, target_name, source_name, access_level, source_trust_domain,
	active_revision, active_source_svid_regex, current_source_svid_regex, active_auth_config, active_spec,
	secret_store_instance, expires_at, updated_at`

// Row is a row of v_active_bindings.
type Row struct {
	ID                  uuid.UUID
	Name                string
	PlatformType        string
	Platform            string
	TargetName          string
	SourceName          string
	AccessLevel         string
	TrustDomain         string
	ActiveRevision      int64
	ActiveRegex         string
	SourceRegex         string
	AuthConfig          json.RawMessage
	Spec                json.RawMessage
	SecretStoreInstance string
	ExpiresAt           *time.Time
	UpdatedAt           time.Time
}

// Binding is a resolved binding, with both of its regexes compiled.
type Binding struct {
	Row
	active, source *regexp.Regexp
}

// Options are the settings of server.workload_listener.resolution_cache.
type Options struct {
	FullReloadInterval time.Duration
	MaxStaleness       time.Duration
	Policy             regexpolicy.Policy
}

// Cache is the resolution cache of one replica.
type Cache struct {
	pool *pgxpool.Pool // the reader pool
	opts Options
	now  func() time.Time

	mu       sync.RWMutex
	byID     map[uuid.UUID]*Binding
	byDomain map[string][]*Binding // sorted by name
	synced   time.Time             // last successful full reload

	invalid atomic.Int64
}

// New returns an empty cache reading v_active_bindings from pool.
func New(pool *pgxpool.Pool, opts Options) *Cache {
	return &Cache{pool: pool, opts: opts, now: time.Now, byID: map[uuid.UUID]*Binding{}, byDomain: map[string][]*Binding{}}
}

// InvalidRegexes counts the rows excluded because a regex failed the
// Appendix A validator (ligo_resolution_invalid_regex_total).
func (c *Cache) InvalidRegexes() int64 { return c.invalid.Load() }

// Ready reports whether the cache has been loaded at least once.
func (c *Cache) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.synced.IsZero()
}

// Resolve returns the bindings of the caller (§4.5 rule 5), sorted by name,
// optionally only those to target and of platformType.
func (c *Cache) Resolve(caller spiffeid.ID, target, platformType string) ([]Binding, error) {
	now := c.now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.synced.IsZero() || now.Sub(c.synced) > c.opts.MaxStaleness {
		return nil, ErrStale
	}
	id := caller.String()
	var out []Binding
	for _, b := range c.byDomain[caller.TrustDomain().Name()] {
		if target != "" && b.TargetName != target || platformType != "" && b.PlatformType != platformType {
			continue
		}
		if b.ExpiresAt != nil && !now.Before(*b.ExpiresAt) {
			continue
		}
		if b.active.MatchString(id) && b.source.MatchString(id) {
			out = append(out, *b)
		}
	}
	return out, nil
}

// TargetFlows reads the target flows of the bindings ids from
// v_active_binding_flows (§4.5 rule 6), per binding.
func (c *Cache) TargetFlows(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]flows.Flow, error) {
	list := make([]string, len(ids))
	for i, id := range ids {
		list[i] = id.String()
	}
	rows, err := c.pool.Query(ctx, `SELECT binding_id, name, purpose, protocol, destination, ports::text, tls, coalesce(server_name, ''),
		coalesce(description, '') FROM v_active_binding_flows WHERE binding_id = ANY($1::uuid[])`, list)
	if err != nil {
		return nil, fmt.Errorf("resolution: target flows: %w", err)
	}
	out := map[uuid.UUID][]flows.Flow{}
	_, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (struct{}, error) {
		var id uuid.UUID
		var f flows.Flow
		var ports string
		if err := row.Scan(&id, &f.Name, &f.Purpose, &f.Protocol, &f.Destination, &ports, &f.TLS, &f.ServerName, &f.Description); err != nil {
			return struct{}{}, err
		}
		if f.Ports, err = flows.ParseMultirange(ports); err != nil {
			return struct{}{}, err
		}
		out[id] = append(out[id], f)
		return struct{}{}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("resolution: target flows: %w", err)
	}
	return out, nil
}

// compile validates and compiles both regexes of a row; a row that fails is
// excluded (INV-15).
func (c *Cache) compile(r Row) (*Binding, bool) {
	active, err := regexpolicy.ValidateSVIDRegex(r.ActiveRegex, r.TrustDomain, c.opts.Policy)
	if err == nil {
		var source *regexp.Regexp
		if source, err = regexpolicy.ValidateSVIDRegex(r.SourceRegex, r.TrustDomain, c.opts.Policy); err == nil {
			return &Binding{Row: r, active: active, source: source}, true
		}
	}
	c.invalid.Add(1)
	slog.Error("binding excluded from resolution: invalid regex", "binding", r.Name, "binding_id", r.ID, "error", err)
	return nil, false
}

// replace installs a full load.
func (c *Cache) replace(rows []Row, at time.Time) {
	byID := make(map[uuid.UUID]*Binding, len(rows))
	byDomain := map[string][]*Binding{}
	for _, r := range rows {
		if b, ok := c.compile(r); ok {
			byID[r.ID] = b
			byDomain[r.TrustDomain] = append(byDomain[r.TrustDomain], b)
		}
	}
	for _, list := range byDomain {
		sortByName(list)
	}
	c.mu.Lock()
	c.byID, c.byDomain, c.synced = byID, byDomain, at
	c.mu.Unlock()
}

// upsert installs one reloaded row, or evicts it when its regexes are
// invalid.
func (c *Cache) upsert(r Row) {
	b, ok := c.compile(r)
	if !ok {
		c.evict(r.ID)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(r.ID)
	c.byID[r.ID] = b
	list := append(c.byDomain[r.TrustDomain], b)
	sortByName(list)
	c.byDomain[r.TrustDomain] = list
}

// evict removes a binding that left the view.
func (c *Cache) evict(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(id)
}

func (c *Cache) removeLocked(id uuid.UUID) {
	old, ok := c.byID[id]
	if !ok {
		return
	}
	delete(c.byID, id)
	c.byDomain[old.TrustDomain] = slices.DeleteFunc(c.byDomain[old.TrustDomain], func(b *Binding) bool { return b.ID == id })
}

func sortByName(list []*Binding) {
	slices.SortFunc(list, func(a, b *Binding) int { return strings.Compare(a.Name, b.Name) })
}

// Load reads the whole view (§4.5 rule 1).
func (c *Cache) Load(ctx context.Context) error {
	rows, err := c.pool.Query(ctx, "SELECT "+viewColumns+" FROM v_active_bindings")
	if err != nil {
		return fmt.Errorf("resolution: load: %w", err)
	}
	loaded, err := pgx.CollectRows(rows, scanRow)
	if err != nil {
		return fmt.Errorf("resolution: load: %w", err)
	}
	c.replace(loaded, c.now())
	return nil
}

// reload refreshes one binding after a notification (§4.5 rule 3): it is
// replaced, or evicted when it left the view.
func (c *Cache) reload(ctx context.Context, id uuid.UUID) error {
	rows, err := c.pool.Query(ctx, "SELECT "+viewColumns+" FROM v_active_bindings WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("resolution: reload: %w", err)
	}
	r, err := pgx.CollectExactlyOneRow(rows, scanRow)
	if errors.Is(err, pgx.ErrNoRows) {
		c.evict(id)
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolution: reload: %w", err)
	}
	c.upsert(r)
	return nil
}

func scanRow(rows pgx.CollectableRow) (Row, error) {
	var r Row
	var store *string
	err := rows.Scan(&r.ID, &r.Name, &r.PlatformType, &r.Platform, &r.TargetName, &r.SourceName, &r.AccessLevel,
		&r.TrustDomain, &r.ActiveRevision, &r.ActiveRegex, &r.SourceRegex, &r.AuthConfig, &r.Spec, &store,
		&r.ExpiresAt, &r.UpdatedAt)
	if store != nil {
		r.SecretStoreInstance = *store
	}
	return r, err
}

// Run keeps the cache fresh until ctx ends: LISTEN for changes, and a full
// reload every FullReloadInterval (§4.5 rule 3). A lost connection is
// retried; if refreshing fails for longer than MaxStaleness, Resolve fails.
func (c *Cache) Run(ctx context.Context) error {
	for {
		err := c.listen(ctx)
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("resolution cache: listener lost, reconnecting", "error", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

// listen holds one connection with LISTEN, applies the notifications, and
// reloads everything on start (nothing missed while not listening) and
// every FullReloadInterval.
func (c *Cache) listen(ctx context.Context) error {
	conn, err := c.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}
	if err := c.Load(ctx); err != nil {
		return err
	}
	next := time.Now().Add(c.opts.FullReloadInterval)
	for {
		wait, cancel := context.WithDeadline(ctx, next)
		n, err := conn.Conn().WaitForNotification(wait)
		cancel()
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err != nil && wait.Err() != nil: // the reload is due
			if err := c.Load(ctx); err != nil {
				return err
			}
			next = time.Now().Add(c.opts.FullReloadInterval)
		case err != nil:
			return err
		default:
			if err := c.notified(ctx, n.Payload); err != nil {
				return err
			}
		}
	}
}

// notified applies one notification: a binding ID reloads that binding;
// "source:<id>" reloads everything, since the view does not name the
// source's bindings.
func (c *Cache) notified(ctx context.Context, payload string) error {
	if strings.HasPrefix(payload, "source:") {
		return c.Load(ctx)
	}
	id, err := uuid.Parse(payload)
	if err != nil {
		slog.Warn("resolution cache: unexpected notification", "payload", payload)
		return nil
	}
	return c.reload(ctx, id)
}
