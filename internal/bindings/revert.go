package bindings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/jackc/pgx/v5"
)

// actorRevert files the reverts of expired break-glass changes (§6.3).
const actorRevert = "system:break-glass-expiry"

// WarnBreakGlass marks the open break-glass changes expiring within the
// shortest warn_before of their sides' policies, once each, and audits
// BREAK_GLASS_EXPIRING (§6.3).
func (s *Service) WarnBreakGlass(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT b.id, b.name, b.break_glass_cr_id, b.break_glass_expires_at, array_agg(sd.scope)
		FROM bindings b JOIN change_request_sides sd ON sd.change_request_id = b.break_glass_cr_id AND sd.basis = 'BREAK_GLASS'
		WHERE b.break_glass_cr_id IS NOT NULL AND b.break_glass_warned_at IS NULL GROUP BY b.id`)
	if err != nil {
		return err
	}
	type open struct {
		id, cr    uuid.UUID
		name      string
		expiresAt time.Time
		scopes    []string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (open, error) {
		var o open
		return o, r.Scan(&o.id, &o.name, &o.cr, &o.expiresAt, &o.scopes)
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, o := range list {
		warn := time.Duration(0)
		for _, sc := range o.scopes {
			if p := s.Requests.Policy.BreakGlassPolicyFor(sc); p != nil && (warn == 0 || p.WarnBefore < warn) {
				warn = p.WarnBefore
			}
		}
		if time.Until(o.expiresAt) > warn {
			continue
		}
		errs = append(errs, pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE bindings SET break_glass_warned_at = now()
				WHERE id = $1 AND break_glass_cr_id = $2 AND break_glass_warned_at IS NULL`, o.id, o.cr)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			snap, _ := json.Marshal(map[string]any{"expiresAt": o.expiresAt.UTC().Format(time.RFC3339)})
			_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &o.id, ResourceName: o.name,
				ChangeRequestID: &o.cr, Action: "BREAK_GLASS_EXPIRING", Actor: actorRevert, Snapshot: snap})
			return err
		}))
	}
	return errors.Join(errs...)
}

// RevertExpired reverts the break-glass changes past their TTL whose
// binding is not busy, during maintenance too; a busy binding waits for the
// next run, a failed revert for an operator (§6.3, INV-16).
func (s *Service) RevertExpired(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT b.break_glass_cr_id FROM bindings b
		WHERE b.break_glass_expires_at < now() AND b.phase IN ('ACTIVE', 'FAILED')
		AND NOT EXISTS (SELECT 1 FROM change_requests v WHERE v.reverts_cr_id = b.break_glass_cr_id
			AND v.status <> 'FAILED_TO_APPLY' OR v.reverts_cr_id = b.break_glass_cr_id AND v.apply_error NOT LIKE 'binding-busy%')`)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		r, err := s.Requests.Read(ctx, id)
		if err == nil {
			_, err = s.revert(ctx, r, actorRevert)
		}
		if e := (*changerequests.Error)(nil); errors.As(err, &e) {
			continue // a refused revert is recorded FAILED_TO_APPLY: busy ones are retried, failed ones alerted
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("break-glass change %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// RevertNow reverts an open break-glass CREATE or UPDATE at once, for its
// requester or an approver of one of its sides (§7.2.3 "Revert now").
func (s *Service) RevertNow(ctx context.Context, c changerequests.Caller, id uuid.UUID) (*changerequests.Request, error) {
	r, err := s.Requests.Read(ctx, id)
	if err == nil && c.ID() != r.RequestedBy && !slices.ContainsFunc(r.Sides, func(sd changerequests.Side) bool { return c.Grants.CanApprove(sd.Scope) }) {
		err = pgx.ErrNoRows // the requester holds break_glass only, which sees nothing
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refuse(404, "not-found", "change request %s", id)
	}
	if err != nil {
		return nil, err
	}
	if r.Kind != changerequests.KindBreakGlass || r.ResourceType != "BINDING" || r.Operation == "DELETE" {
		return nil, refuse(409, "break-glass-not-open", "change request %s is no break-glass CREATE or UPDATE of a binding", id)
	}
	return s.revert(ctx, r, c.ID())
}

// revert files and applies the SYSTEM_REVERT of bg: a DELETE of a created
// binding, else an UPDATE to its revert payload, re-validated without RBAC.
// A payload that no longer validates is a failed revert (§6.3).
func (s *Service) revert(ctx context.Context, bg *changerequests.Request, actor string) (*changerequests.Request, error) {
	cur, err := load(ctx, s.DB, "b.id = $1", *bg.ResourceID, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refuse(409, "break-glass-not-open", "the binding of %s is gone", bg.ID)
	}
	if err != nil {
		return nil, err
	}
	if err := s.withdrawPending(ctx, cur, actor); err != nil {
		return nil, err
	}
	r := &changerequests.Request{ResourceType: "BINDING", ResourceName: cur.name, ResourceID: &cur.id, Operation: "DELETE",
		Kind: changerequests.KindSystemRevert, Consent: changerequests.ConsentAny, Zone: cur.zone, SourceScope: cur.sourceScope,
		TargetScope: cur.targetScope, PlatformScope: cur.platformScope, ExpectedRevision: &cur.revision, Payload: json.RawMessage("{}"),
		RequestedBy: actor, RevertsID: &bg.ID}
	for _, sd := range bg.Sides {
		r.Sides = append(r.Sides, changerequests.Side{Name: sd.Name, Scope: sd.Scope, Basis: changerequests.KindSystemRevert,
			Decision: changerequests.Approved, DecidedBy: changerequests.RevertApprover})
	}
	if bg.Operation == "UPDATE" {
		r.Operation = "UPDATE"
		var b Binding
		err := json.Unmarshal(bg.RevertPayload, &b)
		if err == nil {
			err = s.revalidate(ctx, &b, cur)
		}
		if r.Payload, _ = json.Marshal(b); err != nil {
			if err := s.Requests.SystemFailed(ctx, r, err.Error(), audit.Entry{ResourceType: "BINDING", ResourceID: &cur.id,
				ResourceName: cur.name, Action: "BREAK_GLASS_REVERT_FAILED", Actor: actor, Revision: &cur.revision}); err != nil {
				return nil, err
			}
			return r, err
		}
	}
	return r, s.Requests.System(ctx, r)
}

// revalidate runs the creation pipeline on a revert payload: no RBAC, but
// the interconnection policy in force (§6.3).
func (s *Service) revalidate(ctx context.Context, b *Binding, cur *stored) error {
	p := s.Requests.Policy
	res, err := s.resolve(ctx, nil, b, cur, p, changerequests.ConsentAny, nil)
	if err != nil {
		return err
	}
	if d := p.Evaluate(res.sourceScope, res.targetScope); !d.Allowed {
		return refuse(403, "interconnect-denied", "the interconnection policy denies %s to %s (rule %s)", res.sourceScope, res.targetScope, d.Rule)
	}
	return nil
}

// RetireInlineSources retires the inline source of each reverted
// break-glass CREATE once its binding is gone, unless the source has other
// bindings by then (§6.3 "Inline source").
func (s *Service) RetireInlineSources(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT d.id, d.resource_id FROM change_requests c
		JOIN change_requests d ON d.id = c.depends_on_cr_id JOIN sources src ON src.id = d.resource_id
		WHERE c.kind = 'BREAK_GLASS' AND d.kind = 'BREAK_GLASS' AND src.state <> 'RETIRED'
		AND EXISTS (SELECT 1 FROM change_requests v WHERE v.reverts_cr_id = c.id AND v.status = 'APPLIED')
		AND NOT EXISTS (SELECT 1 FROM bindings b WHERE b.id = c.resource_id OR b.source_id = src.id)
		AND NOT EXISTS (SELECT 1 FROM change_requests v WHERE v.reverts_cr_id = d.id AND v.status = 'APPLIED')`)
	if err != nil {
		return err
	}
	type inline struct{ cr, source uuid.UUID }
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (inline, error) {
		var i inline
		return i, r.Scan(&i.cr, &i.source)
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, i := range list {
		r, err := s.Sources.Retirement(ctx, i.source)
		if err == nil {
			r.Kind, r.Consent, r.RequestedBy, r.RevertsID = changerequests.KindSystemRevert, changerequests.ConsentAny, actorRevert, &i.cr
			r.Sides = []changerequests.Side{{Name: "OWNER", Scope: r.OwnerScope, Basis: changerequests.KindSystemRevert,
				Decision: changerequests.Approved, DecidedBy: changerequests.RevertApprover}}
			err = s.Requests.System(ctx, r)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("inline source %s: %w", i.source, err))
		}
	}
	return errors.Join(errs...)
}

// OverdueReviews marks the unratified break-glass changes past their TTL
// that no applied revert undid (emergency deletes, deleted bindings, inline
// sources kept for other bindings), once each, and audits
// BREAK_GLASS_REVIEW_OVERDUE (§6.3).
func (s *Service) OverdueReviews(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE change_requests c SET review_overdue_notified_at = now()
			WHERE c.kind = 'BREAK_GLASS' AND c.status = 'APPLIED' AND c.review_overdue_notified_at IS NULL
			AND c.requested_at + make_interval(secs => c.break_glass_ttl_seconds) < now()
			AND EXISTS (SELECT 1 FROM change_request_sides sd WHERE sd.change_request_id = c.id AND sd.basis = 'BREAK_GLASS'
				AND sd.ratified_by IS NULL)
			AND NOT EXISTS (SELECT 1 FROM change_requests v WHERE v.reverts_cr_id = c.id AND v.status = 'APPLIED')
			AND NOT EXISTS (SELECT 1 FROM bindings b WHERE b.break_glass_cr_id = c.id)
			AND (c.resource_type <> 'SOURCE' OR EXISTS (SELECT 1 FROM bindings b WHERE b.source_id = c.resource_id
				AND NOT EXISTS (SELECT 1 FROM change_requests x WHERE x.depends_on_cr_id = c.id AND x.resource_id = b.id)))
			RETURNING c.id, c.resource_type, c.resource_name, c.resource_id`)
		if err != nil {
			return err
		}
		var entries []audit.Entry
		for rows.Next() {
			e := audit.Entry{Action: "BREAK_GLASS_REVIEW_OVERDUE", Actor: actorRevert}
			var id uuid.UUID
			if err := rows.Scan(&id, &e.ResourceType, &e.ResourceName, &e.ResourceID); err != nil {
				rows.Close()
				return err
			}
			e.ChangeRequestID = &id
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, e := range entries {
			if _, err := audit.Append(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
}
