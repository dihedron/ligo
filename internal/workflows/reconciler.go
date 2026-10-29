package workflows

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/jackc/pgx/v5"
)

// Reconciler re-applies ACTIVE bindings on a schedule, one replica at a
// time: it repairs drift on the targets and rotates static secrets (§6.6).
type Reconciler struct {
	Engine        *Engine
	Interval      time.Duration            // reconciliation.interval; default 6h
	Jitter        time.Duration            // reconciliation.jitter
	MaxConcurrent int                      // re-applies running at once; default 4
	Rotation      map[string]time.Duration // rotation_interval per platform
}

// Run reconciles every Interval plus a random jitter until ctx ends.
func (r *Reconciler) Run(ctx context.Context) {
	interval := r.Interval
	if interval == 0 {
		interval = 6 * time.Hour
	}
	for {
		wait := interval
		if r.Jitter > 0 {
			wait += time.Duration(rand.Int64N(int64(r.Jitter))) // #nosec G404 -- spreading load, not a secret
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			_, _ = r.Reconcile(ctx)
		}
	}
}

// Reconcile starts re-applies of ACTIVE bindings, oldest transition first,
// up to MaxConcurrent running at once, if this replica holds the lock
// ligo_reconciler and maintenance mode is off; it returns how many it
// started.
func (r *Reconciler) Reconcile(ctx context.Context) (int, error) {
	db := r.Engine.DB
	conn, err := db.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var locked, maintenance bool
	var running int
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext('ligo_reconciler'))").Scan(&locked); err != nil || !locked {
		return 0, err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext('ligo_reconciler'))")
	}()
	if err := db.QueryRow(ctx, `SELECT (SELECT maintenance_mode FROM system_settings),
		(SELECT count(*) FROM bindings WHERE phase = 'PROVISIONING' AND operation = 'REAPPLY')`).Scan(&maintenance, &running); err != nil {
		return 0, err
	}
	limit := r.MaxConcurrent
	if limit == 0 {
		limit = 4
	}
	if maintenance || running >= limit {
		return 0, nil
	}
	rows, err := db.Query(ctx, `SELECT id, platform FROM bindings WHERE phase = 'ACTIVE' ORDER BY last_transition_at LIMIT $1`, limit-running)
	if err != nil {
		return 0, err
	}
	type due struct {
		id       uuid.UUID
		platform string
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (due, error) {
		var d due
		return d, row.Scan(&d.id, &d.platform)
	})
	if err != nil {
		return 0, err
	}
	started := 0
	var errs []error
	for _, d := range list {
		ok, err := r.reapply(ctx, d.id, r.Rotation[d.platform])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok {
			continue // busy since the query
		}
		started++
		if _, err := r.Engine.Start(ctx, d.id); err != nil {
			errs = append(errs, err) // the sweeper starts it
		}
	}
	return started, errors.Join(errs...)
}

// reapply moves an ACTIVE binding to a REAPPLY attempt: same revision, a
// new attempt and workflow, and rotation for a static secret whose
// rotation_interval has passed (§6.4 rotation flag); it reports false if
// the binding is no longer ACTIVE.
func (r *Reconciler) reapply(ctx context.Context, id uuid.UUID, rotation time.Duration) (bool, error) {
	ok := false
	err := pgx.BeginFunc(ctx, r.Engine.DB, func(tx pgx.Tx) error {
		var name string
		var revision, attempt int64
		err := tx.QueryRow(ctx, `UPDATE bindings b SET phase = 'PROVISIONING', operation = 'REAPPLY', attempt = attempt + 1,
			workflow_id = format('ligo:reapply:%s:r%s:a%s', id, revision, attempt + 1), current_step = 'INIT', status_message = '',
			rotate_static_secrets = coalesce((SELECT s.artifact->>'mode' IN ('IDENTITY_MODE_EXTERNAL_DIR', 'IDENTITY_MODE_TARGET_LOCAL')
				FROM binding_stage_state s WHERE s.binding_id = b.id AND s.stage = 'IDENTITY'), false)
				AND (last_rotated_at IS NULL OR last_rotated_at < now() - $2::interval),
			last_transition_at = now(), updated_at = now()
			WHERE id = $1 AND phase = 'ACTIVE' RETURNING name, revision, attempt`, id, rotation.String()).Scan(&name, &revision, &attempt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		ok = true
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &id, ResourceName: name, Action: "REAPPLY_STARTED",
			Actor: "system:reconciler", Revision: &revision, Attempt: &attempt})
		return err
	})
	return ok, err
}
