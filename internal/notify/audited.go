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
	"CONFIG_PLATFORM_CHANGED", "PROPAGATION_FAILED", "SYSTEM_INTERCONNECT_VIOLATIONS", "SYSTEM_PRIVILEGE_BOUND_VIOLATIONS", "SYSTEM_MAINTENANCE_ENABLED",
	"SYSTEM_MAINTENANCE_DISABLED", "SYSTEM_EXECUTOR_RECOVERED", "BINDING_TARGET_DECIDED_BY_PLATFORM"}

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
	realm, operation, consent, kind, requestedBy string
	jurisdictions                                [4]*string // owner, source, target, platform
	justification, incident                      *string
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
	var jurisdictions []string
	var cr *request
	if e.ChangeRequestID != nil {
		cr = &request{}
		err := tx.QueryRow(ctx, `SELECT coalesce(realm, ''), operation, consent, kind, requested_by, owner_jurisdiction, source_jurisdiction, target_jurisdiction,
			platform_jurisdiction, break_glass_justification, external_approval_ref FROM change_requests WHERE id = $1`, *e.ChangeRequestID).
			Scan(&cr.realm, &cr.operation, &cr.consent, &cr.kind, &cr.requestedBy, &cr.jurisdictions[0], &cr.jurisdictions[1], &cr.jurisdictions[2], &cr.jurisdictions[3],
				&cr.justification, &cr.incident)
		if err != nil {
			return nil, err
		}
		p["changeRequestId"], p["operation"] = e.ChangeRequestID.String(), cr.operation
		if cr.realm != "" {
			p["realm"] = cr.realm
		}
		for i, key := range []string{"ownerJurisdiction", "sourceJurisdiction", "targetJurisdiction", "platformJurisdiction"} {
			if s := cr.jurisdictions[i]; s != nil {
				p[key] = *s
				jurisdictions = append(jurisdictions, *s)
			}
		}
		if cr.kind == "BREAK_GLASS" {
			p["justification"], p["incidentReference"] = cr.justification, cr.incident
		}
	}
	if e.ResourceType == "BINDING" {
		var realm, source, target, platform string
		var bs [3]string
		var expires *time.Time
		err := tx.QueryRow(ctx, `SELECT b.realm, s.name, t.name, b.platform, b.source_jurisdiction, b.target_jurisdiction, b.platform_jurisdiction,
			coalesce(b.break_glass_expires_at, b.expires_at) FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id
			WHERE b.name = $1`, e.ResourceName).Scan(&realm, &source, &target, &platform, &bs[0], &bs[1], &bs[2], &expires)
		switch {
		case err == nil:
			resource["source"], resource["target"], resource["platform"] = source, target, platform
			p["realm"], p["sourceJurisdiction"], p["targetJurisdiction"], p["platformJurisdiction"] = realm, bs[0], bs[1], bs[2]
			if expires != nil {
				p["expiresAt"] = expires.UTC().Format(time.RFC3339)
			}
			jurisdictions = append(jurisdictions, bs[:]...)
		case !errors.Is(err, pgx.ErrNoRows): // a deleted binding is announced with its request's jurisdictions
			return nil, err
		}
	}
	slices.Sort(jurisdictions)
	jurisdictions = slices.Compact(jurisdictions)
	switch name {
	case "CR_AWAITING_APPROVAL": // one per pending side, to its own jurisdiction
		return o.awaiting(ctx, tx, *e.ChangeRequestID, p)
	case "BINDING_REVOKED": // a revocation or downgrade by one side, to the other jurisdictions
		if cr == nil || e.ResourceType != "BINDING" || cr.consent != "ANY" {
			return nil, nil
		}
		deciding, err := collect(ctx, tx, "SELECT jurisdiction FROM change_request_sides WHERE change_request_id = $1 AND decision = 'APPROVED'", *e.ChangeRequestID)
		if err != nil {
			return nil, err
		}
		jurisdictions = slices.DeleteFunc(jurisdictions, func(s string) bool { return slices.Contains(deciding, s) })
		if len(jurisdictions) == 0 { // every side decided, as in a break-glass revert: nobody else to tell
			return nil, nil
		}
	case "PROPAGATION_FAILED": // a revision the propagator could not compose, or one it started that failed
		if e.Action == "PROPAGATION_FAILED" {
			break
		}
		var propagated bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_log WHERE action = 'PROPAGATION_STARTED' AND resource_type = 'BINDING'
			AND resource_id = $1 AND revision = $2)`, e.ResourceID, e.Revision).Scan(&propagated); err != nil || !propagated {
			return nil, err
		}
	case "SOURCE_DEPRECATED", "TARGET_DEPRECATED", "ACCESS_LEVEL_DEPRECATED": // to the jurisdictions of the affected bindings
		var err error
		if jurisdictions, err = o.affected(ctx, tx, name, e); err != nil {
			return nil, err
		}
	case "BINDING_TARGET_DECIDED_BY_PLATFORM": // to the target's account, which did not take part (.specs/ligo-tenancy.md §9.3)
		if cr == nil || cr.jurisdictions[2] == nil {
			return nil, nil
		}
		jurisdictions = []string{*cr.jurisdictions[2]}
	case "CR_INTERCONNECT_DENIED": // no change request: the jurisdictions are in the snapshot
		var snap struct{ SourceJurisdiction, TargetJurisdiction string }
		_ = json.Unmarshal(e.Snapshot, &snap)
		jurisdictions = []string{snap.SourceJurisdiction, snap.TargetJurisdiction}
		p["sourceJurisdiction"], p["targetJurisdiction"] = snap.SourceJurisdiction, snap.TargetJurisdiction
	}
	return []Event{{Name: name, Jurisdictions: jurisdictions, Payload: p}}, nil
}

// awaiting is CR_AWAITING_APPROVAL for each side of the request still to
// be decided.
func (o *Outbox) awaiting(ctx context.Context, tx pgx.Tx, crID any, p map[string]any) ([]Event, error) {
	rows, err := tx.Query(ctx, "SELECT side, jurisdiction FROM change_request_sides WHERE change_request_id = $1 AND decision IS NULL ORDER BY side", crID)
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
		payload["side"], payload["sideJurisdiction"] = sd[0], sd[1]
		out = append(out, Event{Name: "CR_AWAITING_APPROVAL", Jurisdictions: []string{sd[1]}, Payload: payload})
	}
	return out, nil
}

// affected are the jurisdictions of the bindings of a deprecated source, target
// or access level.
func (o *Outbox) affected(ctx context.Context, tx pgx.Tx, name string, e audit.Entry) ([]string, error) {
	q := `SELECT DISTINCT unnest(ARRAY[b.source_jurisdiction, b.target_jurisdiction, b.platform_jurisdiction]::text[]) FROM bindings b `
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
