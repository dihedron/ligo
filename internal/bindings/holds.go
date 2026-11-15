package bindings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
)

// Holds (.specs/ligo-managed-resources.md §3.5). A person's emergency
// deletion or containment of a managed binding leaves a hold on its name and
// on its (source, target, access level): until a person lifts it, or the
// review of a break-glass deletion ratifies it, nobody files that binding
// again, the owner's automation included.

// checkHold refuses a creation that an open hold stands against.
func checkHold(ctx context.Context, q store.Querier, name, source, target, level string) error {
	var id uuid.UUID
	var held string
	err := q.QueryRow(ctx, `SELECT id, binding_name FROM managed_holds WHERE lifted_at IS NULL
		AND (binding_name = $1 OR (source = $2 AND target = $3 AND access_level = $4)) LIMIT 1`, name, source, target, level).Scan(&id, &held)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("bindings: holds: %w", err)
	}
	return refuse(409, "resource-held", "binding %q is held (hold %s on %q): a person must lift the hold first", name, id, held)
}

// createHold records the hold that the deletion r of the managed binding cur
// leaves, if it leaves one: a containment, that is a deletion with consent
// ANY by someone other than the owner, or an emergency deletion. System
// reverts and expiries, and the owner's own deletions, leave none.
func createHold(ctx context.Context, tx pgx.Tx, r *changerequests.Request, cur *stored) ([]audit.Entry, error) {
	var basis string
	switch {
	case cur.managedBy == "":
		return nil, nil
	case r.Kind == changerequests.KindBreakGlass:
		basis = "BREAK_GLASS"
	case (r.Kind == "" || r.Kind == "STANDARD") && r.Consent == changerequests.ConsentAny && r.RequestedBy != cur.managedBy:
		basis = "CONTAINMENT"
	default:
		return nil, nil
	}
	id := uuid.NewV7()
	if _, err := tx.Exec(ctx, `INSERT INTO managed_holds (id, binding_name, source, target, access_level, source_jurisdiction, target_jurisdiction,
		platform_jurisdiction, managed_by, basis, deleted_by, change_request_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		id, cur.name, cur.source, cur.target, cur.accessLevel, cur.sourceJurisdiction, cur.targetJurisdiction, cur.platformJurisdiction,
		cur.managedBy, basis, r.RequestedBy, r.ID); err != nil {
		return nil, fmt.Errorf("bindings: hold: %w", err)
	}
	snap, _ := json.Marshal(map[string]any{"holdId": id, "basis": basis, "managedBy": cur.managedBy})
	return []audit.Entry{{ResourceType: "BINDING", ResourceID: &cur.id, ResourceName: cur.name, ChangeRequestID: &r.ID, Action: "HOLD_CREATED", Snapshot: snap}}, nil
}

// liftRatified ends the open hold of the break-glass deletion id, whose
// review has just been ratified by actor.
func liftRatified(ctx context.Context, tx pgx.Tx, id uuid.UUID, name, actor string) ([]audit.Entry, error) {
	var hold uuid.UUID
	err := tx.QueryRow(ctx, `UPDATE managed_holds SET lifted_by = $2, lifted_at = now(), lift_basis = 'RATIFIED'
		WHERE change_request_id = $1 AND lifted_at IS NULL RETURNING id`, id, actor).Scan(&hold)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	snap, _ := json.Marshal(map[string]any{"holdId": hold, "basis": "RATIFIED"})
	return []audit.Entry{{ResourceType: "BINDING", ResourceName: name, ChangeRequestID: &id, Action: "HOLD_LIFTED", Actor: actor, Approver: actor, Snapshot: snap}}, nil
}

// LiftHold lifts the hold id (a person's act, never a tool's): the caller
// must approve a side of the held binding, and says why. It only restores
// the right to ask: the creation is filed and approved as any other.
func (s *Service) LiftHold(ctx context.Context, c changerequests.Caller, id, comment string) error {
	hold, err := uuid.Parse(id)
	if err != nil {
		return invalid("hold id: %v", err)
	}
	if strings.TrimSpace(comment) == "" {
		return invalid("comment is required")
	}
	if c.Principal.SPIFFEID != "" {
		return refuse(403, "forbidden", "a hold is lifted by a person, not by %s", c.ID())
	}
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var name, sj, tj, pj string
		var lifted bool
		err := tx.QueryRow(ctx, `SELECT binding_name, source_jurisdiction, target_jurisdiction, platform_jurisdiction, lifted_at IS NOT NULL
			FROM managed_holds WHERE id = $1 FOR UPDATE`, hold).Scan(&name, &sj, &tj, &pj, &lifted)
		if errors.Is(err, pgx.ErrNoRows) {
			return refuse(404, "not-found", "hold %s", id)
		}
		if err != nil {
			return err
		}
		if !c.Grants.CanApprove(sj) && !c.Grants.CanApprove(tj) && !c.Grants.CanApprove(pj) {
			return refuse(403, "forbidden", "%s approves no side of binding %q", c.ID(), name)
		}
		if lifted {
			return refuse(409, "resource-held", "hold %s is already lifted", id)
		}
		if _, err := tx.Exec(ctx, `UPDATE managed_holds SET lifted_by = $2, lifted_at = now(), lift_basis = 'PERSON', lift_comment = $3 WHERE id = $1`,
			hold, c.ID(), comment); err != nil {
			return err
		}
		snap, _ := json.Marshal(map[string]any{"holdId": hold, "basis": "PERSON", "comment": comment})
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceName: name, Action: "HOLD_LIFTED", Actor: c.ID(), Approver: c.ID(), Snapshot: snap})
		return err
	})
}
