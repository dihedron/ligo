package bindings

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/jackc/pgx/v5"
)

// actorPropagator is the actor of propagation re-applies; it also marks
// the bindings they keep PROVISIONING.
const actorPropagator = "system:propagator"

// Propagator re-applies the bindings queued by applied source and target
// changes at new revisions, one replica at a time (§6.8).
type Propagator struct {
	Service       *Service
	Interval      time.Duration // propagation.interval; default 5s
	MaxConcurrent int           // propagation.max_concurrent; default 8
}

// Run propagates every Interval until ctx ends.
func (p *Propagator) Run(ctx context.Context) {
	interval := p.Interval
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
			_, _ = p.Propagate(ctx)
		}
	}
}

// Propagate starts re-applies of queued bindings, narrowings (priority 0)
// first, up to MaxConcurrent running at once, if this replica holds the
// lock ligo_propagator; in maintenance mode only narrowings start. Busy
// bindings keep their rows. It returns how many it started.
func (p *Propagator) Propagate(ctx context.Context) (int, error) {
	db := p.Service.DB
	conn, err := db.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var locked, maintenance bool
	var running int
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext('ligo_propagator'))").Scan(&locked); err != nil || !locked {
		return 0, err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext('ligo_propagator'))")
	}()
	if err := db.QueryRow(ctx, `SELECT (SELECT maintenance_mode FROM system_settings),
		(SELECT count(*) FROM bindings WHERE phase = 'PROVISIONING' AND updated_by = $1)`, actorPropagator).Scan(&maintenance, &running); err != nil {
		return 0, err
	}
	limit := p.MaxConcurrent
	if limit == 0 {
		limit = 8
	}
	rows, err := db.Query(ctx, `SELECT binding_id FROM binding_propagation_queue WHERE priority = 0 OR NOT $1
		ORDER BY priority, enqueued_at`, maintenance)
	if err != nil {
		return 0, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	started := 0
	var errs []error
	for _, id := range list {
		if running+started >= limit {
			break
		}
		ok, err := p.Service.propagate(ctx, id)
		if err != nil {
			errs = append(errs, err) // the row stays: retried on the next run
			continue
		}
		if !ok {
			continue
		}
		started++
		if p.Service.Start != nil {
			if err := p.Service.Start(ctx, id); err != nil {
				errs = append(errs, err) // the sweeper starts it
			}
		}
	}
	return started, errors.Join(errs...)
}

// propagate composes and starts the next revision of a queued binding
// from its current source and target (§6.2.2, trigger "propagation"); it
// reports false if the binding was busy (deferred) or the row is gone.
func (s *Service) propagate(ctx context.Context, id uuid.UUID) (bool, error) {
	cur, err := load(ctx, s.DB, "b.id = $1", id, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // deleted: its row went with it
	}
	if err != nil {
		return false, err
	}
	if cur.phase == "PROVISIONING" || cur.phase == "DELETING" {
		return false, s.deferPropagation(ctx, cur)
	}
	b := &Binding{Name: cur.name, Source: cur.source, Target: cur.target, AccessLevel: cur.accessLevel, Parameters: cur.parameters,
		Purpose: cur.purpose, Labels: cur.labels, ExpiresAt: cur.expiresAt}
	// no caller: the change was approved on the source or target (§6.8)
	if _, err := s.resolve(ctx, nil, b, cur, &governance.Policy{}, ""); err != nil {
		return false, err
	}
	started := false
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		sn, err := lockSnapshot(ctx, tx, b)
		if err != nil {
			return err
		}
		if sn.srcRev != b.SourceRevision || sn.tgtRev != b.TargetRevision {
			return nil // changed again since validation: the next run composes it
		}
		if cur, err = load(ctx, tx, "b.id = $1", id, true); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		var cause string
		var causeCR uuid.UUID
		err = tx.QueryRow(ctx, "DELETE FROM binding_propagation_queue WHERE binding_id = $1 RETURNING cause, cause_change_request_id",
			id).Scan(&cause, &causeCR)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // an update meanwhile included the change
		}
		if err != nil {
			return err
		}
		switch cur.phase {
		case "PROVISIONING", "DELETING":
			return errBusy // keep the row: deferred by the next run
		case "DELETE_FAILED":
			return nil // never re-applied: the row goes
		}
		revision, attempt, err := revise(ctx, tx, cur, b, sn, actorPropagator)
		if err != nil {
			return err
		}
		started = true
		snapshot, _ := json.Marshal(map[string]any{"cause": cause, "previousRevision": cur.revision})
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &id, ResourceName: cur.name, ChangeRequestID: &causeCR,
			Action: "PROPAGATION_STARTED", Actor: actorPropagator, Revision: &revision, Attempt: &attempt,
			WorkflowID: workflowID(id, revision, attempt), Snapshot: snapshot})
		return err
	})
	if errors.Is(err, errBusy) {
		return false, nil
	}
	return started, err
}

var errBusy = errors.New("bindings: busy")

// deferPropagation counts a deferral of a busy binding's row, auditing the
// first one (§6.8).
func (s *Service) deferPropagation(ctx context.Context, cur *stored) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var attempts int
		var causeCR uuid.UUID
		err := tx.QueryRow(ctx, `UPDATE binding_propagation_queue SET attempts = attempts + 1 WHERE binding_id = $1
			RETURNING attempts, cause_change_request_id`, cur.id).Scan(&attempts, &causeCR)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && attempts > 1 {
			return nil
		}
		if err != nil {
			return err
		}
		snapshot, _ := json.Marshal(map[string]any{"phase": cur.phase})
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &cur.id, ResourceName: cur.name, ChangeRequestID: &causeCR,
			Action: "PROPAGATION_DEFERRED", Actor: actorPropagator, Revision: &cur.revision, Snapshot: snapshot})
		return err
	})
}
