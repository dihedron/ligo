package changerequests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/metrics"
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
	// Recheck fails, with charter-changed, a request that the
	// policy now in force would refuse or give other sides.
	Recheck(r *Request, p *charter.Policy) error
}

// Differ is a Resource that shows how a request changes the current
// revision of its resource (§7.2.3).
type Differ interface {
	Diff(ctx context.Context, r *Request) (any, error)
}

// DiffOf is the diff of r against its resource, or nil.
func (s *Service) DiffOf(ctx context.Context, r *Request) (any, error) {
	if d, ok := s.Resources[r.ResourceType].(Differ); ok && r.Operation == "UPDATE" {
		return d.Diff(ctx, r)
	}
	return nil, nil
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
	Policy    *charter.Policy
	TTL       time.Duration // change_request_ttl
	Resources map[string]Resource
	// BreakGlassRules are the request-level break-glass rules (ADR-12); the
	// per-jurisdiction policies are the Policy's.
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

// CreateDependent files a source CREATE and the binding CREATE that names
// it, in one transaction (§7.2.4 "Inline source"): the binding depends on
// the source's request, and applies with it when both are complete at
// creation, or later once the source's request is applied.
func (s *Service) CreateDependent(ctx context.Context, c Caller, approvalReference string, source, binding Filing) error {
	items := make([]filed, 2)
	for i, f := range []Filing{source, binding} {
		res, err := s.resource(f.Request)
		if err != nil {
			return err
		}
		if f.Request.Sides, err = BuildSides(f.Candidates, c, s.Policy, approvalReference); err != nil {
			return err
		}
		if err := s.stamp(c, f.Request, approvalReference); err != nil {
			return err
		}
		items[i] = filed{res, f.Request}
	}
	binding.Request.DependsOn = &source.Request.ID
	return s.file(ctx, items...)
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
// CheckEmergency checks the fields a person gives with a break-glass change
// (ADR-12 rule 2), all of them, before anything else is looked at: the
// justification, the incident reference, and a TTL (0 for the default)
// within 5m and 24h; the policies' max_ttl is checked once the sides are
// known. The error carries a message per field.
func (s *Service) CheckEmergency(justification, incident string, ttl time.Duration) error {
	fields := map[string]string{}
	if n := max(s.BreakGlassRules.MinJustificationLength, 20); len([]rune(justification)) < n {
		fields["justification"] = fmt.Sprintf("At least %d characters.", n)
	}
	if incident == "" {
		fields["incidentReference"] = "Required."
	} else if p := s.BreakGlassRules.IncidentReferencePattern; p != "" {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		if !re.MatchString(incident) {
			fields["incidentReference"] = "Does not match the pattern " + p + "."
		}
	}
	if ttl != 0 && (ttl < 5*time.Minute || ttl > 24*time.Hour) {
		fields["ttl"] = "Between 5m and 24h (the break-glass policy may allow less)."
	}
	if len(fields) == 0 {
		return nil
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		parts = append(parts, k+": "+fields[k])
	}
	e := refuse(422, "validation-failed", "%s", strings.Join(parts, "; "))
	e.Fields = fields
	return e
}

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
	if err := s.CheckEmergency(r.Justification, incident, r.TTL); err != nil {
		return err
	}
	maxTTL, defaultTTL := 24*time.Hour, 24*time.Hour
	for _, sd := range sides {
		if sd.Basis != BasisBreakGlass {
			continue
		}
		p := s.Policy.BreakGlassPolicyFor(sd.Jurisdiction)
		if p == nil {
			return refuse(403, "forbidden", "no break-glass policy covers %s", sd.Jurisdiction)
		}
		maxTTL, defaultTTL = min(maxTTL, p.MaxTTL), min(defaultTTL, p.DefaultTTL)
	}
	if r.TTL == 0 {
		r.TTL = defaultTTL
	}
	if r.TTL < 5*time.Minute || r.TTL > maxTTL {
		e := refuse(422, "validation-failed", "ttl %s: between 5m and %s", r.TTL, maxTTL)
		e.Fields = map[string]string{"ttl": "Between 5m and " + maxTTL.String() + ", the break-glass policy's maximum for these sides."}
		return e
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

// withdrawPending withdraws the pending request on r's resource, if any, in
// the name of r's requester, and adds its audit entry to entries.
func withdrawPending(ctx context.Context, tx pgx.Tx, r *Request, entries []audit.Entry) ([]audit.Entry, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM change_requests WHERE resource_type = $1 AND resource_name = $2 AND status = 'PENDING' FOR UPDATE`,
		r.ResourceType, r.ResourceName).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}
	if err := store.CloseRequest(ctx, tx, id, "WITHDRAWN", r.RequestedBy, "superseded by a system change", ""); err != nil {
		return nil, err
	}
	return append(entries, audit.Entry{ResourceType: r.ResourceType, ResourceID: r.ResourceID, ResourceName: r.ResourceName,
		ChangeRequestID: &id, Action: "CR_WITHDRAWN", Actor: r.RequestedBy}), nil
}

// appliedIn reports whether the request id of items was applied.
func appliedIn(items []filed, id uuid.UUID) bool {
	return slices.ContainsFunc(items, func(it filed) bool { return it.r.ID == id && it.r.Status == "APPLIED" })
}

// filed is a request and its resource.
type filed struct {
	res Resource
	r   *Request
}

// checkOpen refuses a break-glass change whose sides would exceed their
// policy's max_open unratified break-glass changes, each counted once per
// policy. It runs in the filing transaction, under a lock all break-glass
// filings share, so concurrent ones are counted one after the other.
// OpenBreakGlass is the SQL condition, over a change request r and one of
// its sides s, of an unratified side of a break-glass change that is still
// open (ADR-12): a binding CREATE or UPDATE while its binding references it
// (ratifying every side, a revert or a delete clears that), an emergency
// DELETE until its TTL ends. An inline source's change is not counted on its
// own: it is ratified and reverted with its binding's.
const OpenBreakGlass = `r.kind = 'BREAK_GLASS' AND r.status = 'APPLIED' AND r.resource_type = 'BINDING'
	AND s.basis = 'BREAK_GLASS' AND s.ratified_by IS NULL
	AND CASE WHEN r.operation = 'DELETE' THEN r.requested_at + make_interval(secs => r.break_glass_ttl_seconds) > now()
		ELSE EXISTS (SELECT 1 FROM bindings b WHERE b.break_glass_cr_id = r.id) END`

func (s *Service) checkOpen(ctx context.Context, tx pgx.Tx, items []filed) error {
	var policies []*charter.BreakGlassPolicy
	for _, it := range items {
		for _, sd := range it.r.Sides {
			if p := s.Policy.BreakGlassPolicyFor(sd.Jurisdiction); sd.Basis == BasisBreakGlass && p != nil && !slices.Contains(policies, p) {
				policies = append(policies, p)
			}
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ligo_break_glass'))`); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT r.id, s.jurisdiction FROM change_requests r
		JOIN change_request_sides s ON s.change_request_id = r.id WHERE `+OpenBreakGlass)
	if err != nil {
		return err
	}
	type open struct {
		id           uuid.UUID
		jurisdiction string
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (open, error) {
		var o open
		return o, row.Scan(&o.id, &o.jurisdiction)
	})
	if err != nil {
		return err
	}
	for _, p := range policies {
		ids := map[uuid.UUID]bool{}
		for _, o := range list {
			if s.Policy.BreakGlassPolicyFor(o.jurisdiction) == p {
				ids[o.id] = true
			}
		}
		if len(ids) >= p.MaxOpen {
			return refuse(429, "break-glass-limit", "the break-glass policy of %v has %d open changes", p.Jurisdictions, len(ids))
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

// sameAtApproval are the refusals an approval answers as filing does
// (.specs/ligo-tenancy.md §5, §7.2); all others read validation-failed (§7.2.3).
var sameAtApproval = []string{"account-not-registered", "account-jurisdiction-mismatch", "namespace-mismatch", "namespace-jurisdiction-mismatch"}

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

// SetMaintenance turns maintenance mode on or off and audits it in one
// transaction; the UPDATE waits for the changes that already passed the
// check (§10.3).
func SetMaintenance(ctx context.Context, db *pgxpool.Pool, actor string, groups []string, enabled bool, reason string) error {
	action := "SYSTEM_MAINTENANCE_DISABLED"
	if enabled {
		action = "SYSTEM_MAINTENANCE_ENABLED"
	}
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE system_settings SET maintenance_mode = $1, maintenance_reason = nullif($2, ''),
			changed_by = $3, changed_at = now()`, enabled, reason, actor); err != nil {
			return err
		}
		snap, _ := json.Marshal(map[string]string{"reason": reason})
		_, err := audit.Append(ctx, tx, audit.Entry{Action: action, Actor: actor, ActorGroups: groups, Snapshot: snap})
		return err
	})
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
		entries, err := withdrawPending(ctx, tx, r, nil) // as file does: it would hold the name
		if err != nil {
			return err
		}
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
		return appendAll(ctx, tx, append(append(entries, entry(r, "CR_CREATED", r.RequestedBy, "", nil),
			entry(r, "CR_APPLY_FAILED", decider, "", map[string]any{"error": limit(reason)})), extra...))
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
		if items[0].r.Kind == KindBreakGlass {
			if err := s.checkOpen(ctx, tx, items); err != nil {
				return err
			}
		}
		var entries []audit.Entry
		if k := items[0].r.kind(); k == KindSystemRevert || k == "SYSTEM_EXPIRY" {
			// a system change supersedes the resource's pending request, which
			// would hold its name (uq_cr_one_pending_per_resource)
			var err error
			if entries, err = withdrawPending(ctx, tx, items[0].r, entries); err != nil {
				return err
			}
		}
		for _, it := range items {
			r := it.r
			if err := insert(ctx, tx, r); err != nil {
				return err
			}
			sides := make([]map[string]any, 0, len(r.Sides))
			for _, sd := range r.Sides {
				sides = append(sides, map[string]any{"side": sd.Name, "jurisdiction": sd.Jurisdiction, "basis": sd.Basis})
			}
			entries = append(entries, entry(r, "CR_CREATED", r.RequestedBy, "", map[string]any{"consent": r.Consent, "sides": sides}))
			decider := ""
			for _, sd := range r.Sides {
				if sd.Decision == Approved {
					entries = append(entries, s.sideApproved(r, sd, r.RequestedBy))
					decider = sd.DecidedBy
				}
			}
			// a dependent request waits for its source's (§7.2.4); it cannot be
			// complete without it: its SOURCE side has the source's jurisdiction
			if !Complete(r.Consent, r.Sides) || r.DependsOn != nil && !appliedIn(items, *r.DependsOn) {
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
		for _, sd := range it.r.Sides {
			if sd.Basis == BasisDelegated && sd.Decision == Approved {
				metrics.DelegatedApprovals.WithLabelValues(it.r.RequestedBy, it.r.Realm, it.r.Operation).Inc()
			}
		}
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
	if err := s.dependencyApplied(ctx, r); err != nil {
		return nil, err
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
		detail, slug := err.Error(), "validation-failed"
		if e := (*Error)(nil); errors.As(err, &e) {
			detail = e.Detail
			if slices.Contains(sameAtApproval, e.Slug) {
				slug = e.Slug
			}
		}
		return nil, s.fail(ctx, r, c.ID(), detail, refuse(422, slug, "%s", detail))
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
				e := s.sideApproved(r, sd, c.ID())
				if c.ByPlatform(r, sd) {
					e = markPlatform(e)
					entries = append(entries, e, PlatformDecision(r, sd, Approved, c.ID()))
					continue
				}
				entries = append(entries, e)
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

// dependencyApplied refuses to decide a request whose inline source's
// request is not applied yet (§7.2.4).
func (s *Service) dependencyApplied(ctx context.Context, r *Request) error {
	if r.DependsOn == nil {
		return nil
	}
	var status string
	if err := s.DB.QueryRow(ctx, "SELECT status FROM change_requests WHERE id = $1", *r.DependsOn).Scan(&status); err != nil {
		return err
	}
	if status != "APPLIED" {
		return refuse(409, "dependency-pending", "the change request %s that registers its source is %s", *r.DependsOn, status)
	}
	return nil
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
				e := entry(r, "CR_SIDE_DECLINED", c.ID(), c.ID(), map[string]any{"side": sd.Name, "jurisdiction": sd.Jurisdiction})
				if c.ByPlatform(r, sd) {
					e = markPlatform(e)
					entries = append(entries, e, PlatformDecision(r, sd, Declined, c.ID()))
					continue
				}
				entries = append(entries, e)
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
// jurisdiction of the request and of its sides counts (§7.2.4).
func (s *Service) Get(ctx context.Context, c Caller, id uuid.UUID) (*Request, error) {
	r, err := read(ctx, s.DB, id)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.Grants.Sees(r.jurisdictions()...)) {
		return nil, refuse(404, "not-found", "change request %s", id)
	}
	return r, err
}

// Filter selects change requests (GET /v1/admin/change-requests).
type Filter struct {
	Status, ResourceType, ResourceName, Realm string
	Kind                                      string // BREAK_GLASS for GET /v1/admin/break-glass
	Jurisdiction                              string // a pattern matched against every jurisdiction of the request
	AwaitingMe                                bool   // with a pending side the caller may decide
	Before                                    *uuid.UUID
	Limit                                     int
}

// List returns the change requests c sees that f selects, newest first,
// at most f.Limit, and whether more follow (keyset on id, §7.2.3).
// shortcut: each request is read with its sides (two queries), fine for pages of ≤ 200 on an admin API; aggregate in SQL if lists get hot.
func (s *Service) List(ctx context.Context, c Caller, f Filter) ([]*Request, bool, error) {
	var out []*Request
	before := f.Before
	for {
		rows, err := s.DB.Query(ctx, `SELECT id FROM change_requests WHERE ($1 = '' OR status::text = $1)
			AND ($2 = '' OR resource_type::text = $2) AND ($3 = '' OR resource_name = $3) AND ($4 = '' OR realm = $4)
			AND ($5::uuid IS NULL OR id < $5) AND ($7 = '' OR kind::text = $7) ORDER BY id DESC LIMIT $6`,
			f.Status, f.ResourceType, f.ResourceName, f.Realm, before, 2*f.Limit, f.Kind)
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
			if !c.Grants.Sees(r.jurisdictions()...) || f.Jurisdiction != "" && !slices.ContainsFunc(r.jurisdictions(), func(sc string) bool {
				return charter.JurisdictionMatches(f.Jurisdiction, sc)
			}) {
				continue
			}
			if f.AwaitingMe {
				// only a PENDING request awaits anyone: with consent ANY an applied one keeps sides nobody needs to decide
				if r.Status != "PENDING" {
					continue
				}
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
		if sd.Basis == BasisAuto && s.Policy.ApprovalRequired(sd.Jurisdiction) {
			return refuse(409, "charter-changed", "side %s now needs an approver: file the change again", sd.Name)
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
	snap := map[string]any{"side": sd.Name, "jurisdiction": sd.Jurisdiction, "basis": sd.Basis}
	if sd.Basis == BasisDelegated {
		snap["approvalReference"] = r.ApprovalReference
		if r.AutomationContext != nil {
			snap["automationContext"] = r.AutomationContext
		}
	}
	return entry(r, "CR_SIDE_APPROVED", actor, sd.DecidedBy, snap)
}

// PlatformDecision is the entry that announces a TARGET side decided through
// ByPlatform, for the webhook to the target's account (§9.3).
func PlatformDecision(r *Request, s Side, decision, actor string) audit.Entry {
	return entry(r, "BINDING_TARGET_DECIDED_BY_PLATFORM", actor, actor, map[string]any{"side": s.Name, "jurisdiction": s.Jurisdiction, "decision": decision, "decidedAs": DecidedAsPlatform})
}

// markPlatform adds decidedAs to a side's entry, whose snapshot is an object.
func markPlatform(e audit.Entry) audit.Entry {
	var snap map[string]any
	_ = json.Unmarshal(e.Snapshot, &snap) // written just now, by entry
	snap["decidedAs"] = DecidedAsPlatform
	e.Snapshot, _ = json.Marshal(snap)
	return e
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
		realm, owner_jurisdiction, source_jurisdiction, target_jurisdiction, platform_jurisdiction, policy_sha256, distinct_approvers_required, expected_revision,
		payload, payload_sha256, external_approval_ref, automation_context, requested_by, expires_at, interconnect_rule,
		break_glass_justification, break_glass_ttl_seconds, revert_payload, depends_on_cr_id, reverts_cr_id)
		VALUES ($1, $2, $3, $4, $5, $22, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $23, $24, $25, $26, $27)`,
		r.ID, r.ResourceType, r.ResourceName, r.ResourceID, r.Operation, r.Consent, null(r.Realm), null(r.OwnerJurisdiction),
		null(r.SourceJurisdiction), null(r.TargetJurisdiction), null(r.PlatformJurisdiction), r.PolicySHA256, r.DistinctApprovers, r.ExpectedRevision,
		r.Payload, r.PayloadSHA256, null(r.ApprovalReference), automation, r.RequestedBy, r.ExpiresAt, null(r.InterconnectRule), r.kind(),
		null(r.Justification), null(int64(r.TTL.Seconds())), revert, r.DependsOn, r.RevertsID); err != nil {
		return fmt.Errorf("changerequests: insert: %w", err)
	}
	for _, sd := range r.Sides {
		if _, err := tx.Exec(ctx, `INSERT INTO change_request_sides (change_request_id, side, jurisdiction, approval_required, basis,
			requested_by, cr_kind, decision, decided_by, decided_at, decision_comment)
			VALUES ($1, $2, $3, $4, $5, $6, $9, $7, $8::varchar, CASE WHEN $8::varchar IS NULL THEN NULL ELSE now() END, $10)`,
			r.ID, sd.Name, sd.Jurisdiction, sd.ApprovalRequired, sd.Basis, r.RequestedBy, null(sd.Decision), null(sd.DecidedBy), r.kind(),
			null(limit(sd.Comment))); err != nil {
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
	err := q.QueryRow(ctx, `SELECT resource_type, resource_name, resource_id, operation, consent, coalesce(realm, ''),
		coalesce(owner_jurisdiction, ''), coalesce(source_jurisdiction, ''), coalesce(target_jurisdiction, ''), coalesce(platform_jurisdiction, ''),
		expected_revision, payload, payload_sha256, coalesce(external_approval_ref, ''), automation_context, policy_sha256,
		distinct_approvers_required, status, requested_by, expires_at, coalesce(interconnect_rule, ''), kind,
		coalesce(break_glass_justification, ''), coalesce(break_glass_ttl_seconds, 0), revert_payload, depends_on_cr_id, reverts_cr_id,
		requested_at FROM change_requests WHERE id = $1`, id).Scan(&r.ResourceType, &r.ResourceName, &r.ResourceID, &r.Operation,
		&r.Consent, &r.Realm, &r.OwnerJurisdiction, &r.SourceJurisdiction, &r.TargetJurisdiction, &r.PlatformJurisdiction, &r.ExpectedRevision,
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
	rows, err := q.Query(ctx, `SELECT side, jurisdiction, approval_required, basis, coalesce(decision::text, ''), coalesce(decided_by, ''),
		decided_at, coalesce(decision_comment, ''), coalesce(ratified_by, ''), ratified_at, coalesce(ratification_comment, '')
		FROM change_request_sides WHERE change_request_id = $1 ORDER BY side`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Side, error) {
		var s Side
		err := row.Scan(&s.Name, &s.Jurisdiction, &s.ApprovalRequired, &s.Basis, &s.Decision, &s.DecidedBy, &s.DecidedAt, &s.Comment, &s.RatifiedBy,
			&s.RatifiedAt, &s.RatificationNote)
		return s, err
	})
}
