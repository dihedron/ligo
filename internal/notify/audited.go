package notify

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/config"
	"github.com/jackc/pgx/v5"
)

// sameName are the audit actions that are events of the same name (§7.5).
var sameName = []string{"BREAK_GLASS_USED", "BREAK_GLASS_EXPIRING", "BREAK_GLASS_REVERTED", "BREAK_GLASS_REVERT_FAILED",
	"BREAK_GLASS_RATIFIED", "BREAK_GLASS_REVIEW_OVERDUE", "CR_INTERCONNECT_DENIED", "BINDING_EXPIRED", "SOURCE_DEPRECATED",
	"TARGET_DEPRECATED", "ACCESS_LEVEL_DEPRECATED", "CONFIG_APPROVAL_POLICY_WEAKENED", "CONFIG_GOVERNANCE_POLICY_CHANGED",
	"CONFIG_PLATFORM_CHANGED", "SYSTEM_INTERCONNECT_VIOLATIONS", "SYSTEM_PRIVILEGE_BOUND_VIOLATIONS", "SYSTEM_MAINTENANCE_ENABLED",
	"SYSTEM_MAINTENANCE_DISABLED"}

// derived are the events announced by audit actions of another name.
var derived = map[string]string{"BINDING_EXPIRY_WARNED": "BINDING_EXPIRING", "CR_CREATED": "CR_AWAITING_APPROVAL",
	"CR_APPROVED": "BINDING_REVOKED", "PROVISION_FAILURE": "PROPAGATION_FAILED"}

// event is the event an audit action may announce, or "".
func event(action string) string {
	if slices.Contains(sameName, action) {
		return action
	}
	return derived[action]
}

// Audited is audit.Hook: it writes the events an audit entry announces to
// the outbox, enriched with the entry's change request and binding.
func (o *Outbox) Audited(ctx context.Context, tx pgx.Tx, e audit.Entry) error {
	name := event(e.Action)
	if name == "" || !slices.ContainsFunc(o.Webhooks, func(w config.Webhook) bool { return slices.Contains(w.Events, name) }) {
		return nil // nobody listens: no query
	}
	events, err := o.events(ctx, tx, name, e)
	if err != nil {
		return err
	}
	for _, ev := range events {
		if err := o.Enqueue(ctx, tx, ev); err != nil {
			return err
		}
	}
	return nil
}

// request is what an event says of its change request.
type request struct {
	zone, operation, consent, kind, requestedBy string
	scopes                                      [4]*string // owner, source, target, platform
	justification, incident                     *string
}

// events builds the events of e named name: none when a derived event's
// condition does not hold.
func (o *Outbox) events(ctx context.Context, tx pgx.Tx, name string, e audit.Entry) ([]Event, error) {
	resource := map[string]any{"type": e.ResourceType, "name": e.ResourceName}
	if e.ResourceID != nil {
		resource["id"] = e.ResourceID.String()
	}
	p := map[string]any{"actor": e.Actor, "resource": resource}
	if e.Snapshot != nil {
		p["details"] = json.RawMessage(e.Snapshot)
	}
	var scopes []string
	var cr *request
	if e.ChangeRequestID != nil {
		cr = &request{}
		err := tx.QueryRow(ctx, `SELECT coalesce(zone, ''), operation, consent, kind, requested_by, owner_scope, source_scope, target_scope,
			platform_scope, break_glass_justification, external_approval_ref FROM change_requests WHERE id = $1`, *e.ChangeRequestID).
			Scan(&cr.zone, &cr.operation, &cr.consent, &cr.kind, &cr.requestedBy, &cr.scopes[0], &cr.scopes[1], &cr.scopes[2], &cr.scopes[3],
				&cr.justification, &cr.incident)
		if err != nil {
			return nil, err
		}
		p["changeRequestId"], p["operation"] = e.ChangeRequestID.String(), cr.operation
		if cr.zone != "" {
			p["zone"] = cr.zone
		}
		for i, key := range []string{"ownerScope", "sourceScope", "targetScope", "platformScope"} {
			if s := cr.scopes[i]; s != nil {
				p[key] = *s
				scopes = append(scopes, *s)
			}
		}
		if cr.kind == "BREAK_GLASS" {
			p["justification"], p["incidentReference"] = cr.justification, cr.incident
		}
	}
	if e.ResourceType == "BINDING" {
		var zone, source, target, platform string
		var bs [3]string
		var expires *time.Time
		err := tx.QueryRow(ctx, `SELECT b.zone, s.name, t.name, b.platform, b.source_scope, b.target_scope, b.platform_scope,
			coalesce(b.break_glass_expires_at, b.expires_at) FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id
			WHERE b.name = $1`, e.ResourceName).Scan(&zone, &source, &target, &platform, &bs[0], &bs[1], &bs[2], &expires)
		switch {
		case err == nil:
			resource["source"], resource["target"], resource["platform"] = source, target, platform
			p["zone"], p["sourceScope"], p["targetScope"], p["platformScope"] = zone, bs[0], bs[1], bs[2]
			if expires != nil {
				p["expiresAt"] = expires.UTC().Format(time.RFC3339)
			}
			scopes = append(scopes, bs[:]...)
		case !errors.Is(err, pgx.ErrNoRows): // a deleted binding is announced with its request's scopes
			return nil, err
		}
	}
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	switch name {
	case "CR_AWAITING_APPROVAL": // one per pending side, to its own scope
		return o.awaiting(ctx, tx, *e.ChangeRequestID, p)
	case "BINDING_REVOKED": // a revocation or downgrade by one side, to the other scopes
		if cr == nil || e.ResourceType != "BINDING" || cr.consent != "ANY" {
			return nil, nil
		}
		deciding, err := collect(ctx, tx, "SELECT scope FROM change_request_sides WHERE change_request_id = $1 AND decision = 'APPROVED'", *e.ChangeRequestID)
		if err != nil {
			return nil, err
		}
		scopes = slices.DeleteFunc(scopes, func(s string) bool { return slices.Contains(deciding, s) })
	case "PROPAGATION_FAILED": // only a revision the propagator started
		var propagated bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_log WHERE action = 'PROPAGATION_STARTED' AND resource_type = 'BINDING'
			AND resource_id = $1 AND revision = $2)`, e.ResourceID, e.Revision).Scan(&propagated); err != nil || !propagated {
			return nil, err
		}
	case "SOURCE_DEPRECATED", "TARGET_DEPRECATED", "ACCESS_LEVEL_DEPRECATED": // to the scopes of the affected bindings
		var err error
		if scopes, err = o.affected(ctx, tx, name, e); err != nil {
			return nil, err
		}
	case "CR_INTERCONNECT_DENIED": // no change request: the scopes are in the snapshot
		var snap struct{ SourceScope, TargetScope string }
		_ = json.Unmarshal(e.Snapshot, &snap)
		scopes = []string{snap.SourceScope, snap.TargetScope}
		p["sourceScope"], p["targetScope"] = snap.SourceScope, snap.TargetScope
	}
	return []Event{{Name: name, Scopes: scopes, Payload: p}}, nil
}

// awaiting is CR_AWAITING_APPROVAL for each side of the request still to
// be decided.
func (o *Outbox) awaiting(ctx context.Context, tx pgx.Tx, crID any, p map[string]any) ([]Event, error) {
	rows, err := tx.Query(ctx, "SELECT side, scope FROM change_request_sides WHERE change_request_id = $1 AND decision IS NULL ORDER BY side", crID)
	if err != nil {
		return nil, err
	}
	sides, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([2]string, error) {
		var v [2]string
		return v, r.Scan(&v[0], &v[1])
	})
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, sd := range sides {
		payload := map[string]any{}
		for k, v := range p {
			payload[k] = v
		}
		payload["side"], payload["sideScope"] = sd[0], sd[1]
		out = append(out, Event{Name: "CR_AWAITING_APPROVAL", Scopes: []string{sd[1]}, Payload: payload})
	}
	return out, nil
}

// affected are the scopes of the bindings of a deprecated source, target
// or access level.
func (o *Outbox) affected(ctx context.Context, tx pgx.Tx, name string, e audit.Entry) ([]string, error) {
	q := `SELECT DISTINCT unnest(ARRAY[b.source_scope, b.target_scope, b.platform_scope]::text[]) FROM bindings b `
	switch name {
	case "SOURCE_DEPRECATED":
		return collect(ctx, tx, q+"JOIN sources s ON s.id = b.source_id WHERE s.name = $1", e.ResourceName)
	case "TARGET_DEPRECATED":
		return collect(ctx, tx, q+"JOIN targets t ON t.id = b.target_id WHERE t.name = $1", e.ResourceName)
	}
	var snap struct{ AccessLevel string }
	_ = json.Unmarshal(e.Snapshot, &snap)
	return collect(ctx, tx, q+"JOIN targets t ON t.id = b.target_id WHERE t.name = $1 AND b.access_level = $2", e.ResourceName, snap.AccessLevel)
}

func collect(ctx context.Context, tx pgx.Tx, q string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
