package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
)

// Sweeper is the housekeeping loop one replica runs at a time (§6.3).
type Sweeper struct {
	Engine   *Engine
	Interval time.Duration // between sweeps; default 30s
	Stale    time.Duration // a workflow quieter than this is checked; default 60s
	// Retention is storage.dbos.workflow_retention: finished workflows older
	// than it are purged (§6.7); default 168h.
	Retention time.Duration
}

// Run sweeps every Interval until ctx ends; errors wait for the next tick.
func (s *Sweeper) Run(ctx context.Context) {
	interval := s.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.Sweep(ctx)
		}
	}
}

// Sweep runs one pass if this replica takes the lock ligo_sweeper; it
// reports whether it ran.
func (s *Sweeper) Sweep(ctx context.Context) (bool, error) {
	conn, err := s.Engine.DB.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext('ligo_sweeper'))").Scan(&locked); err != nil || !locked {
		return false, err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext('ligo_sweeper'))") }()
	return true, errors.Join(s.workflows(ctx), s.expire(ctx), s.dependencies(ctx), s.sessions(ctx), s.retain(ctx))
}

// workflows starts the workflow of a stale binding that DBOS does not know
// (AC-19), and fails one whose workflow ended without marking it.
func (s *Sweeper) workflows(ctx context.Context) error {
	stale := s.Stale
	if stale == 0 {
		stale = time.Minute
	}
	rows, err := s.Engine.DB.Query(ctx, `SELECT id, workflow_id FROM bindings
		WHERE phase IN ('PROVISIONING', 'DELETING') AND last_transition_at < now() - $1::interval`, stale.String())
	if err != nil {
		return err
	}
	type pending struct {
		id         uuid.UUID
		workflowID string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pending, error) {
		var p pending
		return p, r.Scan(&p.id, &p.workflowID)
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range list {
		h, err := dbos.RetrieveWorkflow[string](s.Engine.DBOS, p.workflowID)
		if errors.Is(err, dbos.ErrNonExistentWorkflow) {
			if _, err := s.Engine.Start(ctx, p.id); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		st, err := h.GetStatus()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if st.Status == dbos.WorkflowStatusError || st.Status == dbos.WorkflowStatusCancelled {
			in, _, err := s.Engine.input(ctx, p.id)
			if err == nil && in.WorkflowID == p.workflowID {
				err = s.Engine.markFailed(ctx, fence{bindingID: p.id, workflowID: p.workflowID}, "sweeper",
					&StepError{Message: "workflow terminated unexpectedly"}, in)
			}
			if err != nil && !errors.Is(err, store.ErrFenced) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// close closes a pending request with the compare-and-set of §4.3 and
// audits it; a request decided meanwhile is left alone.
func (s *Sweeper) close(ctx context.Context, id uuid.UUID, status, applyError, action string) error {
	return pgx.BeginFunc(ctx, s.Engine.DB, func(tx pgx.Tx) error {
		var typ, name string
		if err := tx.QueryRow(ctx, "SELECT resource_type, resource_name FROM change_requests WHERE id = $1", id).Scan(&typ, &name); err != nil {
			return err
		}
		if err := store.CloseRequest(ctx, tx, id, status, "system:sweeper", "", applyError); err != nil {
			return err
		}
		var snap json.RawMessage
		if applyError != "" {
			snap, _ = json.Marshal(map[string]string{"error": applyError})
		}
		_, err := audit.Append(ctx, tx, audit.Entry{ResourceType: typ, ResourceName: name, ChangeRequestID: &id, Action: action,
			Actor: "system:sweeper", Snapshot: snap})
		return err
	})
}

func (s *Sweeper) closeAll(ctx context.Context, query, status, applyError, action string) error {
	rows, err := s.Engine.DB.Query(ctx, query)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if err := s.close(ctx, id, status, applyError, action); err != nil && !errors.Is(err, store.ErrNotPending) {
			errs = append(errs, fmt.Errorf("change request %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// expire expires the pending requests past expires_at.
func (s *Sweeper) expire(ctx context.Context) error {
	return s.closeAll(ctx, "SELECT id FROM change_requests WHERE status = 'PENDING' AND expires_at < now()", "EXPIRED", "", "CR_EXPIRED")
}

// dependencies fails a pending binding CREATE whose inline source's
// request ended other than APPLIED.
func (s *Sweeper) dependencies(ctx context.Context) error {
	return s.closeAll(ctx, `SELECT b.id FROM change_requests b JOIN change_requests d ON d.id = b.depends_on_cr_id
		WHERE b.status = 'PENDING' AND d.status NOT IN ('PENDING', 'APPLIED')`,
		"FAILED_TO_APPLY", "inline source not registered", "CR_DEPENDENCY_FAILED")
}

// retain purges the finished workflows older than Retention, their step
// outputs (sealed ciphertexts only) included (§6.7, EXT-06).
func (s *Sweeper) retain(ctx context.Context) error {
	retention := s.Retention
	if retention == 0 {
		retention = 168 * time.Hour
	}
	old, err := dbos.ListWorkflows(s.Engine.DBOS, dbos.WithFilterCreatedBefore(time.Now().Add(-retention)), dbos.WithFilterLimit(1000),
		dbos.WithFilterStatus(dbos.WorkflowStatusSuccess, dbos.WorkflowStatusError, dbos.WorkflowStatusCancelled))
	if err != nil || len(old) == 0 {
		return err
	}
	ids := make([]string, len(old))
	for i, w := range old {
		ids[i] = w.ID
	}
	return dbos.DeleteWorkflows(s.Engine.DBOS, ids)
}

// sessions deletes admin sessions expired or revoked over 7 days ago.
func (s *Sweeper) sessions(ctx context.Context) error {
	_, err := s.Engine.DB.Exec(ctx, `DELETE FROM admin_sessions
		WHERE expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days'`)
	return err
}
