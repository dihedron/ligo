package changerequests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/config"
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

// AfterApply is a Resource that acts once an applied request has
// committed: bindings start their workflow (§6.2.2 step 2).
type AfterApply interface {
	Applied(ctx context.Context, r *Request)
}

// applied calls the resource's AfterApply once r's transaction committed.
func applied(ctx context.Context, res Resource, r *Request) {
	if a, ok := res.(AfterApply); ok && r.Status == "APPLIED" {
		a.Applied(ctx, r)
	}
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
	// BreakGlassRules are the request-level break-glass rules (ADR-12); the
	// per-scope policies are the Policy's.
	BreakGlassRules config.BreakGlass
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
	if err := s.stamp(c, r, approvalReference); err != nil {
		return err
	}
	return s.file(ctx, filed{res, r})
}

// stamp fills r's identity, requester, hashes and expiry.
func (s *Service) stamp(c Caller, r *Request, approvalReference string) error {
	var err error
	if r.PayloadSHA256, err = Hash(r.Payload); err != nil {
		return refuse(422, "validation-failed", "payload: %v", err)
	}
	r.ID, r.RequestedBy, r.Status, r.ApprovalReference = uuid.NewV7(), c.ID(), "PENDING", approvalReference
	r.PolicySHA256 = s.Policy.SHA256()
	if r.InterconnectRule == "" {
		r.DistinctApprovers = s.Policy.RequireDistinctApprovers
	}
	r.ExpiresAt = time.Now().Add(s.TTL)
	return nil
}

// Filing is a request to file with the sides it needs.
type Filing struct {
	Request    *Request
	Candidates []Candidate
}

// BreakGlass files the requests of a break-glass change and applies them
// at once, in one transaction (ADR-12, §7.2.3 "Break-glass operations"):
// an inline source first, then the binding, which depends on it. The last
// request carries the justification and the TTL, 0 for the policies'
// default; incident is the incident reference. At least one side must need
// a decision.
func (s *Service) BreakGlass(ctx context.Context, c Caller, incident string, filings ...Filing) error {
	r := filings[len(filings)-1].Request
	items := make([]filed, len(filings))
	var sides []Side
	for i, f := range filings {
		res, err := s.resource(f.Request)
		if err != nil {
			return err
		}
		if f.Request.Sides, err = BreakGlassSides(f.Candidates, c, s.Policy); err != nil {
			return err
		}
		items[i], sides = filed{res, f.Request}, append(sides, f.Request.Sides...)
	}
	if !slices.ContainsFunc(sides, func(sd Side) bool { return sd.Basis == BasisBreakGlass }) {
		return refuse(422, "validation-failed", "no side needs a decision: file a normal change")
	}
	if n := max(s.BreakGlassRules.MinJustificationLength, 20); len([]rune(r.Justification)) < n {
		return refuse(422, "validation-failed", "justification: at least %d characters", n)
	}
	if incident == "" {
		return refuse(422, "validation-failed", "incidentReference is required")
	}
	if p := s.BreakGlassRules.IncidentReferencePattern; p != "" {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		if !re.MatchString(incident) {
			return refuse(422, "validation-failed", "incidentReference %q does not match incident_reference_pattern", incident)
		}
	}
	maxTTL, defaultTTL := 24*time.Hour, 24*time.Hour
	var policies []*governance.BreakGlassPolicy
	for _, sd := range sides {
		if sd.Basis != BasisBreakGlass {
			continue
		}
		p := s.Policy.BreakGlassPolicyFor(sd.Scope)
		if p == nil {
			return refuse(403, "forbidden", "no break-glass policy covers %s", sd.Scope)
		}
		maxTTL, defaultTTL = min(maxTTL, p.MaxTTL), min(defaultTTL, p.DefaultTTL)
		if !slices.Contains(policies, p) {
			policies = append(policies, p)
		}
	}
	if r.TTL == 0 {
		r.TTL = defaultTTL
	}
	if r.TTL < 5*time.Minute || r.TTL > maxTTL {
		return refuse(422, "validation-failed", "ttl %s: between 5m and %s", r.TTL, maxTTL)
	}
	if err := s.checkOpen(ctx, policies); err != nil {
		return err
	}
	for i, it := range items {
		it.r.Kind, it.r.Justification, it.r.TTL = KindBreakGlass, r.Justification, r.TTL
		if err := s.stamp(c, it.r, incident); err != nil {
			return err
		}
		if i > 0 {
			it.r.DependsOn = &items[0].r.ID
		}
	}
	return s.file(ctx, items...)
}

// filed is a request and its resource.
type filed struct {
	res Resource
	r   *Request
}

// checkOpen refuses a change that would exceed a policy's max_open
// unratified break-glass changes, each counted once per policy.
// shortcut: counted before the transaction, so two concurrent emergencies can exceed max_open by one; lock if that matters.
func (s *Service) checkOpen(ctx context.Context, policies []*governance.BreakGlassPolicy) error {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT r.id, s.scope FROM change_requests r
		JOIN change_request_sides s ON s.change_request_id = r.id
		WHERE r.kind = 'BREAK_GLASS' AND r.status = 'APPLIED' AND s.basis = 'BREAK_GLASS' AND s.ratified_by IS NULL
		AND r.requested_at + make_interval(secs => r.break_glass_ttl_seconds) > now()`)
	if err != nil {
		return err
	}
	type open struct {
		id    uuid.UUID
		scope string
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (open, error) {
		var o open
		return o, row.Scan(&o.id, &o.scope)
	})
	if err != nil {
		return err
	}
	for _, p := range policies {
		ids := map[uuid.UUID]bool{}
		for _, o := range list {
			if s.Policy.BreakGlassPolicyFor(o.scope) == p {
				ids[o.id] = true
			}
		}
		if len(ids) >= p.MaxOpen {
			return refuse(429, "break-glass-limit", "the break-glass policy of %v has %d open changes", p.Scopes, len(ids))
		}
	}
	return nil
}

// System files and applies r, a request of a system kind whose sides were
// all decided by the system (SYSTEM_EXPIRY, SYSTEM_REVERT, §6.3); r names
// its requester. A failed apply closes it FAILED_TO_APPLY and is returned.
func (s *Service) System(ctx context.Context, r *Request) error {
	res, err := s.resource(r)
	if err != nil {
		return err
	}
	if r.PayloadSHA256, err = Hash(r.Payload); err != nil {
		return err
	}
	r.ID, r.Status, r.PolicySHA256, r.ExpiresAt = uuid.NewV7(), "PENDING", s.Policy.SHA256(), time.Now().Add(s.TTL)
	return s.file(ctx, filed{res, r})
}

// Maintenance refuses a change while maintenance mode is on: the shared
// lock makes the check race-free, as turning maintenance on waits for the
// transactions that passed it (§6.2.2, §10.3). It is the first statement
// of the transaction (lock hierarchy, §4.3).
func Maintenance(ctx context.Context, tx pgx.Tx) error {
	var on bool
	if err := tx.QueryRow(ctx, "SELECT maintenance_mode FROM system_settings FOR SHARE").Scan(&on); err != nil {
		return err
	}
	if on {
		return refuse(503, "maintenance", "maintenance mode is on")
	}
	return nil
}

// SystemFailed records r, a system request whose validation failed before
// it could apply, as FAILED_TO_APPLY, with extra audit entries (§6.3: a
// revert that no longer validates is a failed revert).
func (s *Service) SystemFailed(ctx context.Context, r *Request, reason string, extra ...audit.Entry) error {
	var err error
	if r.PayloadSHA256, err = Hash(r.Payload); err != nil {
		return err
	}
	r.ID, r.Status, r.PolicySHA256, r.ExpiresAt = uuid.NewV7(), "PENDING", s.Policy.SHA256(), time.Now().Add(s.TTL)
	decider := r.Sides[0].DecidedBy
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if err := insert(ctx, tx, r); err != nil {
			return err
		}
		if err := store.CloseRequest(ctx, tx, r.ID, "FAILED_TO_APPLY", decider, "", limit(reason)); err != nil {
			return err
		}
		r.Status = "FAILED_TO_APPLY"
		for i := range extra {
			extra[i].ChangeRequestID = &r.ID
		}
		return appendAll(ctx, tx, append([]audit.Entry{entry(r, "CR_CREATED", r.RequestedBy, "", nil),
			entry(r, "CR_APPLY_FAILED", decider, "", map[string]any{"error": limit(reason)})}, extra...))
	})
}

// file inserts each request in one transaction and applies it at once if
// its consent rule is satisfied. With several, a failed apply rolls them all
// back: a later request depends on the earlier ones.
func (s *Service) file(ctx context.Context, items ...filed) error {
	var applyErr error
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if k := items[0].r.kind(); k != KindSystemRevert && k != "SYSTEM_EXPIRY" { // system changes run in maintenance too
			if err := Maintenance(ctx, tx); err != nil {
				return err
			}
		}
		var entries []audit.Entry
		for _, it := range items {
			r := it.r
			if err := insert(ctx, tx, r); err != nil {
				return err
			}
			sides := make([]map[string]any, 0, len(r.Sides))
			for _, sd := range r.Sides {
				sides = append(sides, map[string]any{"side": sd.Name, "scope": sd.Scope, "basis": sd.Basis})
			}
			entries = append(entries, entry(r, "CR_CREATED", r.RequestedBy, "", map[string]any{"consent": r.Consent, "sides": sides}))
			decider := ""
			for _, sd := range r.Sides {
				if sd.Decision == Approved {
					entries = append(entries, s.sideApproved(r, sd, r.RequestedBy))
					decider = sd.DecidedBy
				}
			}
			if !Complete(r.Consent, r.Sides) {
				continue
			}
			var err error
			if entries, applyErr, err = s.apply(ctx, tx, r, it.res, decider, entries); err != nil {
				return err
			}
			if applyErr != nil && len(items) > 1 {
				return applyErr
			}
			if r.Kind == KindBreakGlass && applyErr == nil {
				entries = append(entries, entry(r, "BREAK_GLASS_USED", r.RequestedBy, "", map[string]any{"operation": r.Operation,
					"incidentReference": r.ApprovalReference, "justification": r.Justification, "ttlSeconds": int64(r.TTL.Seconds())}))
			}
		}
		return appendAll(ctx, tx, entries)
	})
	if err != nil {
		return err
	}
	for _, it := range items {
		applied(ctx, it.res, it.r)
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
		if err := Maintenance(ctx, tx); err != nil {
			return err
		}
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
	applied(ctx, res, r)
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

// Filter selects change requests (GET /v1/admin/change-requests).
type Filter struct {
	Status, ResourceType, ResourceName, Zone string
	Scope                                    string // a pattern matched against every scope of the request
	AwaitingMe                               bool   // with a pending side the caller may decide
	Before                                   *uuid.UUID
	Limit                                    int
}

// List returns the change requests c sees that f selects, newest first,
// at most f.Limit, and whether more follow (keyset on id, §7.2.3).
// shortcut: each request is read with its sides (two queries), fine for pages of ≤ 200 on an admin API; aggregate in SQL if lists get hot.
func (s *Service) List(ctx context.Context, c Caller, f Filter) ([]*Request, bool, error) {
	var out []*Request
	before := f.Before
	for {
		rows, err := s.DB.Query(ctx, `SELECT id FROM change_requests WHERE ($1 = '' OR status::text = $1)
			AND ($2 = '' OR resource_type::text = $2) AND ($3 = '' OR resource_name = $3) AND ($4 = '' OR zone = $4)
			AND ($5::uuid IS NULL OR id < $5) ORDER BY id DESC LIMIT $6`,
			f.Status, f.ResourceType, f.ResourceName, f.Zone, before, 2*f.Limit)
		if err != nil {
			return nil, false, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return nil, false, err
		}
		for _, id := range ids {
			r, err := read(ctx, s.DB, id)
			if err != nil {
				return nil, false, err
			}
			if !c.Grants.Sees(r.scopes()...) || f.Scope != "" && !slices.ContainsFunc(r.scopes(), func(sc string) bool {
				return governance.ScopeMatches(f.Scope, sc)
			}) {
				continue
			}
			if f.AwaitingMe {
				if names, err := SelectSides(r, c, s.Policy, true, ""); err != nil || len(names) == 0 {
					continue
				}
			}
			if len(out) == f.Limit {
				return out, true, nil
			}
			out = append(out, r)
		}
		if len(ids) < 2*f.Limit {
			return out, false, nil
		}
		before = &ids[len(ids)-1]
	}
}

// Read reads a change request for the system, without visibility checks.
func (s *Service) Read(ctx context.Context, id uuid.UUID) (*Request, error) {
	return read(ctx, s.DB, id)
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
	var automation, revert any
	if r.AutomationContext != nil {
		automation = r.AutomationContext
	}
	if r.RevertPayload != nil {
		revert = r.RevertPayload
	}
	if _, err := tx.Exec(ctx, `INSERT INTO change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent,
		zone, owner_scope, source_scope, target_scope, platform_scope, policy_sha256, distinct_approvers_required, expected_revision,
		payload, payload_sha256, external_approval_ref, automation_context, requested_by, expires_at, interconnect_rule,
		break_glass_justification, break_glass_ttl_seconds, revert_payload, depends_on_cr_id, reverts_cr_id)
		VALUES ($1, $2, $3, $4, $5, $22, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $23, $24, $25, $26, $27)`,
		r.ID, r.ResourceType, r.ResourceName, r.ResourceID, r.Operation, r.Consent, null(r.Zone), null(r.OwnerScope),
		null(r.SourceScope), null(r.TargetScope), null(r.PlatformScope), r.PolicySHA256, r.DistinctApprovers, r.ExpectedRevision,
		r.Payload, r.PayloadSHA256, null(r.ApprovalReference), automation, r.RequestedBy, r.ExpiresAt, null(r.InterconnectRule), r.kind(),
		null(r.Justification), null(int64(r.TTL.Seconds())), revert, r.DependsOn, r.RevertsID); err != nil {
		return fmt.Errorf("changerequests: insert: %w", err)
	}
	for _, sd := range r.Sides {
		if _, err := tx.Exec(ctx, `INSERT INTO change_request_sides (change_request_id, side, scope, approval_required, basis,
			requested_by, cr_kind, decision, decided_by, decided_at)
			VALUES ($1, $2, $3, $4, $5, $6, $9, $7, $8::varchar, CASE WHEN $8::varchar IS NULL THEN NULL ELSE now() END)`,
			r.ID, sd.Name, sd.Scope, sd.ApprovalRequired, sd.Basis, r.RequestedBy, null(sd.Decision), null(sd.DecidedBy), r.kind()); err != nil {
			return fmt.Errorf("changerequests: insert side %s: %w", sd.Name, err)
		}
	}
	return nil
}

func (r *Request) kind() string {
	if r.Kind == "" {
		return "STANDARD"
	}
	return r.Kind
}

func read(ctx context.Context, q store.Querier, id uuid.UUID) (*Request, error) {
	r := &Request{ID: id}
	var ttl int64
	err := q.QueryRow(ctx, `SELECT resource_type, resource_name, resource_id, operation, consent, coalesce(zone, ''),
		coalesce(owner_scope, ''), coalesce(source_scope, ''), coalesce(target_scope, ''), coalesce(platform_scope, ''),
		expected_revision, payload, payload_sha256, coalesce(external_approval_ref, ''), automation_context, policy_sha256,
		distinct_approvers_required, status, requested_by, expires_at, coalesce(interconnect_rule, ''), kind,
		coalesce(break_glass_justification, ''), coalesce(break_glass_ttl_seconds, 0), revert_payload, depends_on_cr_id, reverts_cr_id,
		requested_at FROM change_requests WHERE id = $1`, id).Scan(&r.ResourceType, &r.ResourceName, &r.ResourceID, &r.Operation,
		&r.Consent, &r.Zone, &r.OwnerScope, &r.SourceScope, &r.TargetScope, &r.PlatformScope, &r.ExpectedRevision,
		&r.Payload, &r.PayloadSHA256, &r.ApprovalReference, &r.AutomationContext, &r.PolicySHA256, &r.DistinctApprovers,
		&r.Status, &r.RequestedBy, &r.ExpiresAt, &r.InterconnectRule, &r.Kind, &r.Justification, &ttl, &r.RevertPayload, &r.DependsOn, &r.RevertsID, &r.RequestedAt)
	if err != nil {
		return nil, err
	}
	r.TTL = time.Duration(ttl) * time.Second
	r.Sides, err = loadSides(ctx, q, id)
	return r, err
}

func loadSides(ctx context.Context, q store.Querier, id uuid.UUID) ([]Side, error) {
	rows, err := q.Query(ctx, `SELECT side, scope, approval_required, basis, coalesce(decision::text, ''), coalesce(decided_by, ''),
		decided_at, coalesce(ratified_by, ''), ratified_at, coalesce(ratification_comment, '')
		FROM change_request_sides WHERE change_request_id = $1 ORDER BY side`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Side, error) {
		var s Side
		err := row.Scan(&s.Name, &s.Scope, &s.ApprovalRequired, &s.Basis, &s.Decision, &s.DecidedBy, &s.DecidedAt, &s.RatifiedBy,
			&s.RatifiedAt, &s.RatificationNote)
		return s, err
	})
}
