package bindings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
)

const (
	kindExpiry     = "SYSTEM_EXPIRY"
	actorExpiry    = "system:binding-expiry" // requests the revocation
	expiryApprover = "system:expiry"         // decides its side
)

// WarnExpiry marks the bindings expiring within warning, once each, and
// audits BINDING_EXPIRY_WARNED (§6.3).
func (s *Service) WarnExpiry(ctx context.Context, warning time.Duration) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE bindings SET expiry_warned_at = now()
			WHERE expires_at < now() + $1::interval AND expiry_warned_at IS NULL AND phase NOT IN ('DELETING', 'DELETE_FAILED')
			RETURNING id, name, revision, expires_at`, warning.String())
		if err != nil {
			return err
		}
		type warned struct {
			id        uuid.UUID
			name      string
			revision  int64
			expiresAt time.Time
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (warned, error) {
			var w warned
			return w, r.Scan(&w.id, &w.name, &w.revision, &w.expiresAt)
		})
		if err != nil {
			return err
		}
		for _, w := range list {
			snap, _ := json.Marshal(map[string]any{"expiresAt": w.expiresAt.UTC().Format(time.RFC3339)})
			if _, err := audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &w.id, ResourceName: w.name,
				Action: "BINDING_EXPIRY_WARNED", Actor: actorExpiry, Revision: &w.revision, Snapshot: snap}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Expire revokes each binding past expires_at that is not busy with a
// SYSTEM_EXPIRY change request, during maintenance too; busy ones wait for
// the next run, already unserved (§6.3, INV-25).
func (s *Service) Expire(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, "SELECT id FROM bindings WHERE expires_at < now() AND phase IN ('ACTIVE', 'FAILED')")
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if err := s.expire(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("binding %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) expire(ctx context.Context, id uuid.UUID) error {
	cur, err := load(ctx, s.DB, "b.id = $1", id, false)
	if err != nil {
		return err
	}
	if err := s.withdrawPending(ctx, cur); err != nil {
		return err
	}
	r := &changerequests.Request{ResourceType: "BINDING", ResourceName: cur.name, ResourceID: &cur.id, Operation: "DELETE", Kind: kindExpiry,
		Consent: changerequests.ConsentAny, Zone: cur.zone, SourceScope: cur.sourceScope, TargetScope: cur.targetScope,
		PlatformScope: cur.platformScope, ExpectedRevision: &cur.revision, Payload: json.RawMessage("{}"), RequestedBy: actorExpiry,
		Sides: []changerequests.Side{{Name: "TARGET", Scope: cur.targetScope, Basis: kindExpiry, Decision: changerequests.Approved,
			DecidedBy: expiryApprover}}}
	return s.Requests.System(ctx, r)
}

// withdrawPending withdraws the binding's own pending change request: the
// revocation supersedes it.
func (s *Service) withdrawPending(ctx context.Context, cur *stored) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var crID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM change_requests WHERE resource_type = 'BINDING' AND resource_id = $1 AND status = 'PENDING'`,
			cur.id).Scan(&crID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := store.CloseRequest(ctx, tx, crID, "WITHDRAWN", actorExpiry, "the binding expired", ""); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &cur.id, ResourceName: cur.name,
			ChangeRequestID: &crID, Action: "CR_WITHDRAWN", Actor: actorExpiry})
		return err
	})
}
