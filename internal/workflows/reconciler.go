package workflows

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
)

// Reconciler re-applies ACTIVE bindings on a schedule, one replica at a
// time: it repairs drift on the targets and rotates static secrets (§6.6).
type Reconciler struct {
	Engine        *Engine
	Logger        *slog.Logger                        // errors of a pass; default slog.Default()
	Interval      time.Duration                       // reconciliation.interval; default 6h
	Jitter        time.Duration                       // reconciliation.jitter
	MaxConcurrent int                                 // re-applies running at once; default 4
	Rotation      func(platform string) time.Duration // the platform's rotation_interval, 0 for none
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
			if _, err := r.Reconcile(ctx); err != nil && ctx.Err() == nil {
				cmp.Or(r.Logger, slog.Default()).Error("reconciler", "error", err)
			}
		}
	}
}

// Reconcile starts re-applies of ACTIVE bindings, oldest transition first,
// up to MaxConcurrent running at once, if this replica holds the lock
// ligo_reconciler and maintenance mode is off; it returns how many it
// started.
func (r *Reconciler) Reconcile(ctx context.Context) (int, error) {
	db := r.Engine.DB
	release, locked, err := store.TryLock(ctx, db, "ligo_reconciler")
	if err != nil || !locked {
		return 0, err
	}
	defer release()
	var maintenance bool
	var running int
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
		ok, err := r.Engine.reapply(ctx, d.id, "system:reconciler", false, r.rotation(d.platform))
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
// new attempt and workflow, rotating if rotate is set or, for a static
// secret, once rotation has passed, never if it is 0 (§6.4 rotation flag); it reports false
// if the binding is no longer ACTIVE. Maintenance mode refuses it.
func (e *Engine) reapply(ctx context.Context, id uuid.UUID, actor string, rotate bool, rotation time.Duration) (bool, error) {
	ok := false
	err := pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		if err := changerequests.Maintenance(ctx, tx); err != nil {
			return err
		}
		var name string
		var revision, attempt int64
		err := tx.QueryRow(ctx, `UPDATE bindings b SET phase = 'PROVISIONING', operation = 'REAPPLY', attempt = attempt + 1,
			workflow_id = format('ligo:reapply:%s:r%s:a%s', id, revision, attempt + 1), current_step = 'INIT', status_message = '',
			rotate_static_secrets = $3 OR coalesce((SELECT s.artifact->>'mode' IN ('IDENTITY_MODE_EXTERNAL_DIR', 'IDENTITY_MODE_TARGET_LOCAL')
				FROM binding_stage_state s WHERE s.binding_id = b.id AND s.stage = 'IDENTITY'), false)
				AND $2::interval > interval '0' AND (last_rotated_at IS NULL OR last_rotated_at < now() - $2::interval),
			last_transition_at = now(), updated_at = now(), updated_by = $4
			WHERE id = $1 AND phase = 'ACTIVE' RETURNING name, revision, attempt`, id, rotation.String(), rotate, actor).Scan(&name, &revision, &attempt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		ok = true
		snap, _ := json.Marshal(map[string]bool{"rotate": rotate})
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &id, ResourceName: name, Action: "REAPPLY_STARTED",
			Actor: actor, Revision: &revision, Attempt: &attempt, Snapshot: snap})
		return err
	})
	return ok, err
}

// Rotate starts a re-apply of an ACTIVE binding that rotates its static
// secret now (POST /v1/admin/bindings/{name}/rotate).
func (e *Engine) Rotate(ctx context.Context, bindingID uuid.UUID, actor string) (dbos.WorkflowHandle[string], error) {
	ok, err := e.reapply(ctx, bindingID, actor, true, 0)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &changerequests.Error{Status: 409, Slug: "invalid-transition", Detail: "only an ACTIVE binding is rotated"}
	}
	return e.Start(ctx, bindingID)
}

// rotation is a platform's rotation interval; none without a Rotation.
func (r *Reconciler) rotation(platform string) time.Duration {
	if r.Rotation == nil {
		return 0
	}
	return r.Rotation(platform)
}
