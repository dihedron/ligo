package bindings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/jackc/pgx/v5"
)

// BreakGlassRequest is the body of POST /v1/admin/break-glass (§7.2.3):
// a binding create or update body, or name and expectedRevision for a
// DELETE.
type BreakGlassRequest struct {
	Operation         string          `json:"operation"`
	Binding           json.RawMessage `json:"binding,omitempty"`
	Name              string          `json:"name,omitempty"`
	ExpectedRevision  *int64          `json:"expectedRevision,omitempty"`
	Justification     string          `json:"justification"`
	IncidentReference string          `json:"incidentReference"`
	TTL               string          `json:"ttl,omitempty"`
}

func breakGlassOpen(cur *stored) error {
	return refuse(409, "break-glass-open", "binding %q has an open break-glass change %s", cur.name, cur.breakGlassCR)
}

// BreakGlass applies an emergency change of a binding at once, under the
// controls of ADR-12: break_glass on every side that needs a decision, a
// justification, an incident reference and a TTL. The caller's fresh
// authentication and LDAP group check are the HTTP layer's.
func (s *Service) BreakGlass(ctx context.Context, c changerequests.Caller, body []byte) (*changerequests.Request, error) {
	var in BreakGlassRequest
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return nil, invalid("body: %v", err)
	}
	var ttl time.Duration
	if in.TTL != "" {
		var err error
		if ttl, err = time.ParseDuration(in.TTL); err != nil {
			return nil, invalid("ttl: %v", err)
		}
	}
	var (
		r     *changerequests.Request
		sides []changerequests.Candidate
		err   error
	)
	switch in.Operation {
	case "CREATE", "UPDATE":
		r, sides, err = s.breakGlassChange(ctx, c, &in)
	case "DELETE":
		r, sides, err = s.breakGlassDelete(ctx, c, &in)
	default:
		return nil, invalid("operation must be CREATE, UPDATE or DELETE")
	}
	if err != nil {
		return nil, err
	}
	r.Justification, r.TTL = in.Justification, ttl
	return r, pendingError(s.Requests.BreakGlass(ctx, c, r, sides, in.IncidentReference), r.ResourceName)
}

// breakGlassChange runs the creation pipeline with the break_glass check of
// the sides in place of the operator check (§7.2.3 "Break-glass
// operations"). An UPDATE stores the current requested state to revert to.
// shortcut: an UPDATE always has consent ALL, so a removal-only one needs break_glass on every side; use DELETE to cut access in an emergency.
func (s *Service) breakGlassChange(ctx context.Context, c changerequests.Caller, in *BreakGlassRequest) (*changerequests.Request, []changerequests.Candidate, error) {
	req, err := decode(in.Binding)
	if err != nil {
		return nil, nil, err
	}
	b := req.Binding
	var cur *stored
	if in.Operation == "UPDATE" {
		if req.ExpectedRevision == nil {
			return nil, nil, invalid("expectedRevision is required")
		}
		if cur, err = s.emergencyTarget(ctx, c, b.Name); err != nil {
			return nil, nil, err
		}
		if cur.breakGlassCR != nil {
			return nil, nil, breakGlassOpen(cur)
		}
		if *req.ExpectedRevision != cur.revision {
			return nil, nil, refuse(409, "revision-conflict", "the binding is at revision %d", cur.revision)
		}
	} else if req.ExpectedRevision != nil {
		return nil, nil, invalid("expectedRevision is only for updates")
	}
	p := s.Requests.Policy
	res, err := s.resolve(ctx, nil, &b, cur, p, changerequests.ConsentAll)
	if err != nil {
		return nil, nil, err
	}
	if res.decision = p.Evaluate(res.sourceScope, res.targetScope); !res.decision.Allowed {
		return nil, nil, s.denied(ctx, c, &b, res)
	}
	if err := s.Rules.checkExpiry(b.ExpiresAt, time.Now()); err != nil {
		return nil, nil, err
	}
	r, sides, err := compose(in.Operation, changerequests.ConsentAll, cur, &b, res, &req.Common, nil)
	if err != nil || cur == nil {
		return r, sides, err
	}
	previous := Binding{Kind: "Binding", Name: cur.name, Source: cur.source, Target: cur.target, AccessLevel: cur.accessLevel,
		Parameters: cur.parameters, Purpose: cur.purpose, Labels: cur.labels, ExpiresAt: cur.expiresAt}
	r.RevertPayload, err = json.Marshal(previous)
	return r, sides, err
}

// breakGlassDelete runs the revocation pipeline, where acting for a side
// also includes holding break_glass on it.
func (s *Service) breakGlassDelete(ctx context.Context, c changerequests.Caller, in *BreakGlassRequest) (*changerequests.Request, []changerequests.Candidate, error) {
	if in.ExpectedRevision == nil || in.Binding != nil {
		return nil, nil, invalid("a DELETE takes name and expectedRevision")
	}
	cur, err := s.emergencyTarget(ctx, c, in.Name)
	if err != nil {
		return nil, nil, err
	}
	if *in.ExpectedRevision != cur.revision {
		return nil, nil, refuse(409, "revision-conflict", "the binding is at revision %d", cur.revision)
	}
	res := &resolved{platform: s.Rules.Platforms[cur.platform], sourceScope: cur.sourceScope, targetScope: cur.targetScope,
		platformScope: cur.platformScope}
	res.platform.Zone = cur.zone
	sides := res.anySides(c, true)
	if len(sides) == 0 {
		return nil, nil, refuse(403, "forbidden", "%s holds no break_glass on %s, %s or %s", c.ID(), cur.sourceScope, cur.targetScope, cur.platformScope)
	}
	return compose("DELETE", changerequests.ConsentAny, cur, &Binding{Name: cur.name}, res, &changerequests.Common{ExpectedRevision: in.ExpectedRevision}, sides)
}

// emergencyTarget reads a binding the caller sees, or on one of whose
// scopes it holds break_glass (404 otherwise).
func (s *Service) emergencyTarget(ctx context.Context, c changerequests.Caller, name string) (*stored, error) {
	cur, err := load(ctx, s.DB, "b.name = $1", name, false)
	if err == nil && !c.Grants.Sees(cur.sourceScope, cur.targetScope, cur.platformScope) &&
		!c.Grants.BreakGlass(cur.sourceScope) && !c.Grants.BreakGlass(cur.targetScope) && !c.Grants.BreakGlass(cur.platformScope) {
		err = pgx.ErrNoRows
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refuse(404, "not-found", "binding %q", name)
	}
	return cur, err
}

// Ratify ratifies the caller's sides of a break-glass change of a binding;
// once every BREAK_GLASS side is ratified, the binding's break-glass expiry
// is cleared and nothing is reverted (ADR-12, §7.2.3 "Ratify"). The binding
// row is locked first, so ratify and a revert start exclude each other.
func (s *Service) Ratify(ctx context.Context, c changerequests.Caller, id uuid.UUID, side, comment string) (*changerequests.Request, error) {
	if comment == "" {
		return nil, invalid("comment is required")
	}
	r, err := s.Requests.Get(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if r.Kind != changerequests.KindBreakGlass || r.ResourceType != "BINDING" || r.Status != "APPLIED" {
		return nil, refuse(409, "break-glass-not-open", "change request %s is no applied break-glass change of a binding", id)
	}
	names, err := changerequests.RatifiableSides(r, c, side)
	if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var name string
		var open *uuid.UUID
		err := tx.QueryRow(ctx, "SELECT name, break_glass_cr_id FROM bindings WHERE id = $1 FOR UPDATE", *r.ResourceID).Scan(&name, &open)
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if exists && r.Operation != "DELETE" && (open == nil || *open != id) {
			return refuse(409, "break-glass-not-open", "the break-glass change %s was reverted or closed", id)
		}
		tag, err := tx.Exec(ctx, `UPDATE change_request_sides SET ratified_by = $3, ratified_at = now(), ratification_comment = $4
			WHERE change_request_id = $1 AND side = ANY($2) AND basis = 'BREAK_GLASS' AND ratified_by IS NULL`, id, names, c.ID(), comment)
		if err != nil {
			return err
		}
		if int(tag.RowsAffected()) != len(names) {
			return refuse(409, "break-glass-not-open", "a side was ratified concurrently")
		}
		var left int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM change_request_sides
			WHERE change_request_id = $1 AND basis = 'BREAK_GLASS' AND ratified_by IS NULL`, id).Scan(&left); err != nil {
			return err
		}
		if left == 0 && exists {
			if _, err := tx.Exec(ctx, `UPDATE bindings SET break_glass_cr_id = NULL, break_glass_expires_at = NULL,
				break_glass_warned_at = NULL WHERE id = $1 AND break_glass_cr_id = $2`, *r.ResourceID, id); err != nil {
				return err
			}
		}
		for _, n := range names {
			snap, _ := json.Marshal(map[string]any{"side": n, "fullyRatified": left == 0})
			if _, err := audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: r.ResourceID, ResourceName: r.ResourceName,
				ChangeRequestID: &id, Action: "BREAK_GLASS_RATIFIED", Actor: c.ID(), Approver: c.ID(), Snapshot: snap}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Requests.Get(ctx, c, id)
}
