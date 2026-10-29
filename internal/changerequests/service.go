package changerequests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Resource re-validates and applies the change requests of one resource
// type (§6.2).
type Resource interface {
	// Revalidate re-runs the creation pipeline against the stored request
	// with no transaction open, and returns the normalized payload it
	// rebuilds (approval steps 2 and 3).
	Revalidate(ctx context.Context, r *Request) (json.RawMessage, error)
	// Apply writes the change in tx and returns its audit entries, which
	// are appended last (§4.3). An error leaves the request FAILED_TO_APPLY,
	// except binding-busy at an approval, which leaves it PENDING (§6.2.2).
	Apply(ctx context.Context, tx pgx.Tx, r *Request) ([]audit.Entry, error)
}

// Rechecker is a Resource whose requests also depend on the policy beyond
// their sides' approval requirements (bindings: ADR-14 rule 5).
type Rechecker interface {
	// Recheck fails, with governance-policy-changed, a request that the
	// policy now in force would refuse or give other sides.
	Recheck(r *Request, p *governance.Policy) error
}

// IsBusy reports a binding-busy refusal (§6.2.2).
func IsBusy(err error) bool {
	e := (*Error)(nil)
	return errors.As(err, &e) && e.Slug == "binding-busy"
}

// Service files and decides change requests.
type Service struct {
	DB        *pgxpool.Pool // the app pool
	Policy    *governance.Policy
	TTL       time.Duration // change_request_ttl
	Resources map[string]Resource
}

func (s *Service) resource(r *Request) (Resource, error) {
	res, ok := s.Resources[r.ResourceType]
	if !ok {
		return nil, fmt.Errorf("changerequests: no resource of type %q", r.ResourceType)
	}
	return res, nil
}

// Create files r, needing the consent of candidates, and applies it at once
// if every side was decided at creation (§7.2.3 "Sides at creation"). It
// fills r's identity, hashes, sides and status.
func (s *Service) Create(ctx context.Context, c Caller, r *Request, candidates []Candidate, approvalReference string) error {
	res, err := s.resource(r)
	if err != nil {
		return err
	}
	if r.Sides, err = BuildSides(candidates, c, s.Policy, approvalReference); err != nil {
		return err
	}
	if r.PayloadSHA256, err = Hash(r.Payload); err != nil {
		return refuse(422, "validation-failed", "payload: %v", err)
	}
	r.ID, r.RequestedBy, r.Status, r.ApprovalReference = uuid.NewV7(), c.ID(), "PENDING", approvalReference
	r.PolicySHA256 = s.Policy.SHA256()
	if r.InterconnectRule == "" {
		r.DistinctApprovers = s.Policy.RequireDistinctApprovers
	}
	r.ExpiresAt = time.Now().Add(s.TTL)
	var applyErr error
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if err := insert(ctx, tx, r); err != nil {
			return err
		}
		sides := make([]map[string]any, 0, len(r.Sides))
		for _, sd := range r.Sides {
			sides = append(sides, map[string]any{"side": sd.Name, "scope": sd.Scope, "basis": sd.Basis})
		}
		entries := []audit.Entry{entry(r, "CR_CREATED", r.RequestedBy, "", map[string]any{"consent": r.Consent, "sides": sides})}
		decider := ""
		for _, sd := range r.Sides {
			if sd.Decision == Approved {
				entries = append(entries, s.sideApproved(r, sd, r.RequestedBy))
				decider = sd.DecidedBy
			}
		}
		if Complete(r.Consent, r.Sides) {
			if entries, applyErr, err = s.apply(ctx, tx, r, res, decider, entries); err != nil {
				return err
			}
		}
		return appendAll(ctx, tx, entries)
	})
	if err != nil {
		return err
	}
	return applyErr
}

// Approve approves the caller's sides of a pending request and applies it
// once its consent rule is satisfied (§7.2.3 "Approval", "Deciding sides").
func (s *Service) Approve(ctx context.Context, c Caller, id uuid.UUID, payloadSHA256, side, comment string) (*Request, error) {
	r, err := s.pending(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if payloadSHA256 != r.PayloadSHA256 {
		return nil, refuse(409, "payload-mismatch", "the change request changed since it was displayed")
	}
	names, err := SelectSides(r, c, s.Policy, true, side)
	if err != nil {
		return nil, err
	}
	res, err := s.resource(r)
	if err != nil {
		return nil, err
	}
	payload, err := res.Revalidate(ctx, r)
	if err != nil {
		detail := err.Error()
		if e := (*Error)(nil); errors.As(err, &e) {
			detail = e.Detail
		}
		return nil, s.fail(ctx, r, c.ID(), detail, refuse(422, "validation-failed", "%s", detail))
	}
	if r.Operation != "DELETE" {
		if h, err := Hash(payload); err != nil || h != r.PayloadSHA256 {
			return nil, s.fail(ctx, r, c.ID(), "normalization drift", refuse(409, "normalization-drift", "the change request no longer matches its resources: file it again"))
		}
	}
	var applyErr error
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := store.DecideSides(ctx, tx, id, payloadSHA256, names, Approved, c.ID(), comment); err != nil {
			return decisionError(err)
		}
		if r.Sides, err = loadSides(ctx, tx, id); err != nil {
			return err
		}
		var entries []audit.Entry
		for _, sd := range r.Sides {
			if sd.DecidedBy == c.ID() && sd.Decision == Approved {
				entries = append(entries, s.sideApproved(r, sd, c.ID()))
			}
		}
		if Complete(r.Consent, r.Sides) {
			if entries, applyErr, err = s.apply(ctx, tx, r, res, c.ID(), entries); err != nil {
				return err
			}
			if IsBusy(applyErr) {
				return applyErr // roll back the side decision: the approver approves again later
			}
		}
		return appendAll(ctx, tx, entries)
	})
	if err != nil {
		return nil, err
	}
	return r, applyErr
}

// Decline declines the caller's sides; the request is REJECTED when its
// consent rule can no longer be satisfied (§7.2.3 "Deciding sides" rule 5).
func (s *Service) Decline(ctx context.Context, c Caller, id uuid.UUID, side, comment string) (*Request, error) {
	r, err := s.pending(ctx, c, id)
	if err != nil {
		return nil, err
	}
	names, err := SelectSides(r, c, s.Policy, false, side)
	if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := store.DecideSides(ctx, tx, id, "", names, Declined, c.ID(), comment); err != nil {
			return decisionError(err)
		}
		if r.Sides, err = loadSides(ctx, tx, id); err != nil {
			return err
		}
		var entries []audit.Entry
		for _, sd := range r.Sides {
			if sd.DecidedBy == c.ID() && sd.Decision == Declined {
				entries = append(entries, entry(r, "CR_SIDE_DECLINED", c.ID(), c.ID(), map[string]any{"side": sd.Name, "scope": sd.Scope}))
			}
		}
		if Rejected(r.Consent, r.Sides) {
			if err := store.CloseRequest(ctx, tx, id, "REJECTED", c.ID(), comment, ""); err != nil {
				return decisionError(err)
			}
			r.Status = "REJECTED"
			entries = append(entries, entry(r, "CR_REJECTED", c.ID(), "", nil))
		}
		return appendAll(ctx, tx, entries)
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Withdraw closes a pending request at its requester's wish.
func (s *Service) Withdraw(ctx context.Context, c Caller, id uuid.UUID, comment string) error {
	r, err := s.Get(ctx, c, id)
	if err != nil {
		return err
	}
	if c.ID() != r.RequestedBy {
		return refuse(403, "forbidden", "only the requester can withdraw a change request")
	}
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if err := store.CloseRequest(ctx, tx, id, "WITHDRAWN", c.ID(), comment, ""); err != nil {
			return decisionError(err)
		}
		return appendAll(ctx, tx, []audit.Entry{entry(r, "CR_WITHDRAWN", c.ID(), "", nil)})
	})
}

// Get reads a change request the caller can see (404 otherwise): every
// scope of the request and of its sides counts (§7.2.4).
func (s *Service) Get(ctx context.Context, c Caller, id uuid.UUID) (*Request, error) {
	r, err := read(ctx, s.DB, id)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.Grants.Sees(r.scopes()...)) {
		return nil, refuse(404, "not-found", "change request %s", id)
	}
	return r, err
}

func (s *Service) pending(ctx context.Context, c Caller, id uuid.UUID) (*Request, error) {
	r, err := s.Get(ctx, c, id)
	if err == nil && r.Status != "PENDING" {
		return nil, refuse(409, "change-request-not-pending", "the change request is %s", r.Status)
	}
	return r, err
}

// apply applies r in a savepoint of tx and closes it APPLIED; a failed
// apply is rolled back and closes it FAILED_TO_APPLY instead, returned as
// applyErr while tx still commits. err is a failure of tx itself.
func (s *Service) apply(ctx context.Context, tx pgx.Tx, r *Request, res Resource, actor string, entries []audit.Entry) (_ []audit.Entry, applyErr, err error) {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	var applied []audit.Entry
	applyErr = s.recheck(r, res)
	if applyErr == nil {
		applied, applyErr = res.Apply(ctx, sp, r)
	}
	if applyErr == nil {
		applyErr = sp.Commit(ctx)
	}
	if applyErr != nil {
		_ = sp.Rollback(ctx)
		if err := store.CloseRequest(ctx, tx, r.ID, "FAILED_TO_APPLY", actor, "", limit(applyErr.Error())); err != nil {
			return nil, nil, decisionError(err)
		}
		r.Status = "FAILED_TO_APPLY"
		return append(entries, entry(r, "CR_APPLY_FAILED", actor, "", map[string]any{"error": limit(applyErr.Error())})), applyErr, nil
	}
	if err := store.CloseRequest(ctx, tx, r.ID, "APPLIED", actor, "", ""); err != nil {
		return nil, nil, decisionError(err)
	}
	r.Status = "APPLIED"
	entries = append(entries, entry(r, "CR_APPROVED", actor, "", nil))
	for _, e := range applied {
		if e.ResourceType == "" {
			e.ResourceType, e.ResourceName = r.ResourceType, r.ResourceName
		}
		if e.ChangeRequestID == nil {
			e.ChangeRequestID = &r.ID
		}
		if e.Actor == "" {
			e.Actor = actor
		}
		entries = append(entries, e)
	}
	return entries, nil, nil
}

// recheck re-evaluates the policy now in force before an apply (approval
// step 5): a side decided automatically must still not need a person, and
// the resource may check more.
func (s *Service) recheck(r *Request, res Resource) error {
	for _, sd := range r.Sides {
		if sd.Basis == BasisAuto && s.Policy.ApprovalRequired(sd.Scope) {
			return refuse(409, "governance-policy-changed", "side %s now needs an approver: file the change again", sd.Name)
		}
	}
	if rc, ok := res.(Rechecker); ok {
		return rc.Recheck(r, s.Policy)
	}
	return nil
}

// fail closes a pending request FAILED_TO_APPLY after a failed approval
// step, and returns refusal.
func (s *Service) fail(ctx context.Context, r *Request, actor, reason string, refusal *Error) error {
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if err := store.CloseRequest(ctx, tx, r.ID, "FAILED_TO_APPLY", actor, "", limit(reason)); err != nil {
			return decisionError(err)
		}
		return appendAll(ctx, tx, []audit.Entry{entry(r, "CR_APPLY_FAILED", actor, "", map[string]any{"error": limit(reason)})})
	})
	if err != nil {
		return err
	}
	return refusal
}

func (s *Service) sideApproved(r *Request, sd Side, actor string) audit.Entry {
	snap := map[string]any{"side": sd.Name, "scope": sd.Scope, "basis": sd.Basis}
	if sd.Basis == BasisDelegated {
		snap["approvalReference"] = r.ApprovalReference
		if r.AutomationContext != nil {
			snap["automationContext"] = r.AutomationContext
		}
	}
	return entry(r, "CR_SIDE_APPROVED", actor, sd.DecidedBy, snap)
}

func entry(r *Request, action, actor, approver string, snapshot map[string]any) audit.Entry {
	e := audit.Entry{ResourceType: r.ResourceType, ResourceID: r.ResourceID, ResourceName: r.ResourceName,
		ChangeRequestID: &r.ID, Action: action, Actor: actor, Approver: approver}
	if snapshot != nil {
		e.Snapshot, _ = json.Marshal(snapshot) // maps of strings and JSON values
	}
	return e
}

func appendAll(ctx context.Context, tx pgx.Tx, entries []audit.Entry) error {
	for _, e := range entries {
		if _, err := audit.Append(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

// decisionError maps the compare-and-set failures of §4.3.
func decisionError(err error) error {
	switch {
	case errors.Is(err, store.ErrPayloadMismatch):
		return refuse(409, "payload-mismatch", "the change request changed since it was displayed")
	case errors.Is(err, store.ErrNotPending), errors.Is(err, store.ErrSideTaken):
		return refuse(409, "change-request-not-pending", "the change request was decided concurrently")
	}
	return err
}

// limit cuts a text to the 2048 characters of the comment and error columns.
func limit(s string) string {
	if r := []rune(s); len(r) > 2048 {
		return string(r[:2048])
	}
	return s
}

func null[T comparable](v T) any {
	var zero T
	if v == zero {
		return nil
	}
	return v
}

func insert(ctx context.Context, tx pgx.Tx, r *Request) error {
	var automation any
	if r.AutomationContext != nil {
		automation = r.AutomationContext
	}
	if _, err := tx.Exec(ctx, `INSERT INTO change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent,
		zone, owner_scope, source_scope, target_scope, platform_scope, policy_sha256, distinct_approvers_required, expected_revision,
		payload, payload_sha256, external_approval_ref, automation_context, requested_by, expires_at, interconnect_rule)
		VALUES ($1, $2, $3, $4, $5, 'STANDARD', $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
		r.ID, r.ResourceType, r.ResourceName, r.ResourceID, r.Operation, r.Consent, null(r.Zone), null(r.OwnerScope),
		null(r.SourceScope), null(r.TargetScope), null(r.PlatformScope), r.PolicySHA256, r.DistinctApprovers, r.ExpectedRevision,
		r.Payload, r.PayloadSHA256, null(r.ApprovalReference), automation, r.RequestedBy, r.ExpiresAt, null(r.InterconnectRule)); err != nil {
		return fmt.Errorf("changerequests: insert: %w", err)
	}
	for _, sd := range r.Sides {
		if _, err := tx.Exec(ctx, `INSERT INTO change_request_sides (change_request_id, side, scope, approval_required, basis,
			requested_by, cr_kind, decision, decided_by, decided_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'STANDARD', $7, $8::varchar, CASE WHEN $8::varchar IS NULL THEN NULL ELSE now() END)`,
			r.ID, sd.Name, sd.Scope, sd.ApprovalRequired, sd.Basis, r.RequestedBy, null(sd.Decision), null(sd.DecidedBy)); err != nil {
			return fmt.Errorf("changerequests: insert side %s: %w", sd.Name, err)
		}
	}
	return nil
}

func read(ctx context.Context, q store.Querier, id uuid.UUID) (*Request, error) {
	r := &Request{ID: id}
	err := q.QueryRow(ctx, `SELECT resource_type, resource_name, resource_id, operation, consent, coalesce(zone, ''),
		coalesce(owner_scope, ''), coalesce(source_scope, ''), coalesce(target_scope, ''), coalesce(platform_scope, ''),
		expected_revision, payload, payload_sha256, coalesce(external_approval_ref, ''), automation_context, policy_sha256,
		distinct_approvers_required, status, requested_by, expires_at, coalesce(interconnect_rule, '')
		FROM change_requests WHERE id = $1`, id).Scan(&r.ResourceType, &r.ResourceName, &r.ResourceID, &r.Operation,
		&r.Consent, &r.Zone, &r.OwnerScope, &r.SourceScope, &r.TargetScope, &r.PlatformScope, &r.ExpectedRevision,
		&r.Payload, &r.PayloadSHA256, &r.ApprovalReference, &r.AutomationContext, &r.PolicySHA256, &r.DistinctApprovers,
		&r.Status, &r.RequestedBy, &r.ExpiresAt, &r.InterconnectRule)
	if err != nil {
		return nil, err
	}
	r.Sides, err = loadSides(ctx, q, id)
	return r, err
}

func loadSides(ctx context.Context, q store.Querier, id uuid.UUID) ([]Side, error) {
	rows, err := q.Query(ctx, `SELECT side, scope, approval_required, basis, coalesce(decision::text, ''), coalesce(decided_by, '')
		FROM change_request_sides WHERE change_request_id = $1 ORDER BY side`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Side, error) {
		var s Side
		err := row.Scan(&s.Name, &s.Scope, &s.ApprovalRequired, &s.Basis, &s.Decision, &s.DecidedBy)
		return s, err
	})
}
