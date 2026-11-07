package accounts

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// channel is what trg_accounts_notify notifies.
const channel = "ligo_accounts_changed"

// Registry holds the ACTIVE accounts in memory, for a check made on every
// request: LISTEN for changes, and a full reload every interval, as the
// resolution cache does (.specs/ligo-tenancy.md §7.2).
// shortcut: with the database unreachable it answers from its last load, as no
// change can then be made or decided; add a staleness limit if reads ever
// outlive the database.
type Registry struct {
	db       *pgxpool.Pool
	interval time.Duration

	mu     sync.RWMutex
	active map[string]bool
}

// NewRegistry returns an empty registry: call Load before using it.
func NewRegistry(db *pgxpool.Pool, interval time.Duration) *Registry {
	return &Registry{db: db, interval: interval}
}

// Active reports whether name is registered and ACTIVE.
func (r *Registry) Active(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active[name]
}

// Load reads the ACTIVE accounts.
func (r *Registry) Load(ctx context.Context) error {
	rows, err := r.db.Query(ctx, "SELECT name FROM accounts WHERE status = 'ACTIVE'")
	if err != nil {
		return err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	active := make(map[string]bool, len(names))
	for _, n := range names {
		active[n] = true
	}
	r.mu.Lock()
	r.active = active
	r.mu.Unlock()
	return nil
}

// Run keeps the registry fresh until ctx ends; a lost connection is retried.
func (r *Registry) Run(ctx context.Context) {
	for {
		err := r.listen(ctx)
		if ctx.Err() != nil {
			return
		}
		slog.Warn("account registry: listener lost, reconnecting", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// listen loads after LISTEN, so that nothing is missed while not listening.
func (r *Registry) listen(ctx context.Context) error {
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}
	for {
		if err := r.Load(ctx); err != nil {
			return err
		}
		wait, cancel := context.WithTimeout(ctx, r.interval)
		_, err := conn.Conn().WaitForNotification(wait)
		expired := wait.Err() != nil
		cancel()
		if err != nil && !expired {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}
