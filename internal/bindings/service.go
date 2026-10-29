package bindings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/jcs"
	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service files the change requests of bindings, and is their
// changerequests.Resource.
type Service struct {
	DB       *pgxpool.Pool // the app pool
	Rules    *Rules
	Requests *changerequests.Service
	Validate ValidateBinding
	// Start starts a binding's workflow once its change committed
	// (§6.2.2 step 2); the sweeper starts it if this fails (§6.3).
	Start func(ctx context.Context, bindingID uuid.UUID) error
	// Sources validates the inline source of a break-glass CREATE.
	Sources *sources.Service
}

// Applied starts the workflow of an applied create, update or delete.
func (s *Service) Applied(ctx context.Context, r *changerequests.Request) {
	if s.Start != nil && r.ResourceID != nil {
		_ = s.Start(ctx, *r.ResourceID) // the sweeper retries a failed start
	}
}

// request is the body of a create or an update (§7.2.3).
type request struct {
	Binding
	changerequests.Common
}

func decode(body []byte) (*request, error) {
	var req request
	if err := changerequests.Decode(body, &req, &req.Common); err != nil {
		return nil, err
	}
	if b := req.Binding; b.Kind != "" || b.SourceRevision != 0 || b.TargetRevision != 0 || b.RequestedSpec != nil {
		return nil, invalid("kind, sourceRevision, targetRevision and requestedSpec are set by ligo")
	}
	return &req, nil
}

// Create files a new binding (POST /v1/admin/bindings).
func (s *Service) Create(ctx context.Context, c changerequests.Caller, body []byte) (*changerequests.Request, error) {
	req, err := decode(body)
	if err != nil {
		return nil, err
	}
	if req.ExpectedRevision != nil {
		return nil, invalid("expectedRevision is only for updates")
	}
	b := req.Binding
	res, err := s.resolve(ctx, &c, &b, nil, s.Requests.Policy, changerequests.ConsentAll, nil)
	if err != nil {
		return nil, err
	}
	return s.file(ctx, c, "CREATE", changerequests.ConsentAll, nil, &b, res, &req.Common)
}

// Update files a change of a binding (PUT /v1/admin/bindings/{name}):
// consent ANY when every change removes access (a lower level, an earlier
// expiry), ALL otherwise (ADR-13 rule 5, §3.10).
func (s *Service) Update(ctx context.Context, c changerequests.Caller, name string, body []byte) (*changerequests.Request, error) {
	req, err := decode(body)
	if err != nil {
		return nil, err
	}
	if req.ExpectedRevision == nil {
		return nil, invalid("expectedRevision is required")
	}
	cur, err := s.current(ctx, c, name)
	if err != nil {
		return nil, err
	}
	if cur.breakGlassCR != nil {
		return nil, breakGlassOpen(cur)
	}
	b := req.Binding
	if b.Name == "" {
		b.Name = name
	}
	consent := changerequests.ConsentAll
	if s.removesOnly(ctx, cur, &b) {
		consent = changerequests.ConsentAny
	}
	res, err := s.resolve(ctx, &c, &b, cur, s.Requests.Policy, consent, nil)
	if err != nil {
		return nil, err
	}
	if *req.ExpectedRevision != cur.revision {
		return nil, refuse(409, "revision-conflict", "the binding is at revision %d", cur.revision)
	}
	return s.file(ctx, c, "UPDATE", consent, cur, &b, res, &req.Common)
}

// Delete files the revocation of a binding (DELETE /v1/admin/bindings/{name}):
// consent ANY, decided by any one of the scopes the requester acts for.
func (s *Service) Delete(ctx context.Context, c changerequests.Caller, name string, expectedRevision int64, approvalReference string, automationContext json.RawMessage) (*changerequests.Request, error) {
	common := &changerequests.Common{ExpectedRevision: &expectedRevision, ApprovalReference: approvalReference, AutomationContext: automationContext}
	if err := changerequests.Decode([]byte("{}"), &struct{}{}, common); err != nil {
		return nil, err
	}
	cur, err := s.current(ctx, c, name)
	if err != nil {
		return nil, err
	}
	pl := s.Rules.Platforms[cur.platform]
	res := &resolved{platform: pl, sourceScope: cur.sourceScope, targetScope: cur.targetScope, platformScope: cur.platformScope}
	if err := res.actsFor(c); err != nil {
		return nil, err
	}
	if expectedRevision != cur.revision {
		return nil, refuse(409, "revision-conflict", "the binding is at revision %d", cur.revision)
	}
	return s.file(ctx, c, "DELETE", changerequests.ConsentAny, cur, &Binding{Name: name}, res, common)
}

// current reads a binding the caller can see by name (404 otherwise).
func (s *Service) current(ctx context.Context, c changerequests.Caller, name string) (*stored, error) {
	cur, err := load(ctx, s.DB, "b.name = $1", name, false)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Grants.Sees(cur.sourceScope, cur.targetScope, cur.platformScope) {
		return nil, refuse(404, "not-found", "binding %q", name)
	}
	return cur, err
}

// removesOnly reports whether an update of cur only removes access: a level
// whose privileges are a subset of the current one's, or the same level,
// and an earlier expiry, or the same one, with nothing else changed.
func (s *Service) removesOnly(ctx context.Context, cur *stored, b *Binding) bool {
	params, _ := jcs.Transform(orEmpty(b.Parameters))
	stored, _ := jcs.Transform(orEmpty(cur.parameters))
	if !bytes.Equal(params, stored) || len(changerequests.Changed(
		changerequests.Field{Name: "purpose", Old: cur.purpose, New: b.Purpose},
		changerequests.Field{Name: "labels", Old: cur.labels, New: b.Labels})) > 0 {
		return false
	}
	sameExpiry := cur.expiresAt == nil && b.ExpiresAt == nil || cur.expiresAt != nil && b.ExpiresAt != nil && cur.expiresAt.Equal(*b.ExpiresAt)
	if !sameExpiry && !engine.ExpiryNarrower(cur.expiresAt, b.ExpiresAt) {
		return false
	}
	if b.AccessLevel == cur.accessLevel {
		return !sameExpiry
	}
	var privileges []string
	err := s.DB.QueryRow(ctx, "SELECT privileges FROM target_access_levels WHERE target_id = $1 AND name = $2", cur.targetID, b.AccessLevel).Scan(&privileges)
	return err == nil && engine.PrivilegesNarrower(cur.privileges, privileges)
}

func orEmpty(j json.RawMessage) json.RawMessage {
	if len(j) == 0 {
		return json.RawMessage("{}")
	}
	return j
}

// stored is the part of a binding row its changes need.
type stored struct {
	id, targetID                            uuid.UUID
	name, source, target, accessLevel       string
	sourceScope, targetScope, platformScope string
	platform, phase, purpose, zone          string
	revision, attempt                       int64
	parameters                              json.RawMessage
	labels                                  map[string]string
	expiresAt                               *time.Time
	privileges                              []string   // of the current level
	breakGlassCR                            *uuid.UUID // the open break-glass change (ADR-12)
}

func load(ctx context.Context, q store.Querier, where string, arg any, lock bool) (*stored, error) {
	st := &stored{}
	sql := `SELECT b.id, b.target_id, b.name, s.name, t.name, b.access_level, b.source_scope, b.target_scope, b.platform_scope,
		b.platform, b.phase, coalesce(b.purpose, ''), b.zone, b.revision, b.attempt, b.parameters, b.labels, b.expires_at, l.privileges, b.break_glass_cr_id
		FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id
		JOIN target_access_levels l ON l.target_id = b.target_id AND l.name = b.access_level WHERE ` + where
	if lock {
		sql += " FOR UPDATE OF b"
	}
	err := q.QueryRow(ctx, sql, arg).Scan(&st.id, &st.targetID, &st.name, &st.source, &st.target, &st.accessLevel, &st.sourceScope,
		&st.targetScope, &st.platformScope, &st.platform, &st.phase, &st.purpose, &st.zone, &st.revision, &st.attempt, &st.parameters,
		&st.labels, &st.expiresAt, &st.privileges, &st.breakGlassCR)
	return st, err
}

// resolved is what the pipeline found for a binding change.
type resolved struct {
	platform                                Platform
	sourceScope, targetScope, platformScope string
	decision                                governance.Decision
}

// resolve runs the pipeline (§7.2.3 steps 1 to 10) on b, a new binding if
// cur is nil, and normalizes it. c is nil when the stored request is
// re-validated at approval: RBAC and the interconnection policy are then
// checked by the approval itself (Recheck). A change with consent ANY only
// removes access: it needs no ACTIVE resources and no policy, and the
// platform's owner may file it too.
func (s *Service) resolve(ctx context.Context, c *changerequests.Caller, b *Binding, cur *stored, p *governance.Policy, consent string, inline *sources.Source) (*resolved, error) {
	b.Kind = "Binding"
	if !engine.ValidName(b.Name) {
		return nil, invalid("name %q is not a valid name (§3.8)", b.Name)
	}
	if cur != nil && (b.Name != cur.name || b.Source != cur.source || b.Target != cur.target) {
		return nil, refuse(422, "immutable-field", "the name, source and target of a binding cannot change")
	}
	var src struct {
		id                      uuid.UUID
		revision                int64
		scope, state, td, regex string
		visibility              string
		visibleTo               []string
	}
	if inline != nil { // registered in the same transaction, at revision 1
		src.revision, src.scope, src.state, src.td, src.regex = 1, inline.Metadata.Scope, "ACTIVE", inline.Identity.TrustDomain, inline.Identity.SVIDRegex
	} else {
		err := s.DB.QueryRow(ctx, `SELECT id, revision, scope, state, trust_domain, svid_regex, visibility, visible_to FROM sources
			WHERE name = $1 AND state <> 'RETIRED'`, b.Source).Scan(&src.id, &src.revision, &src.scope, &src.state, &src.td, &src.regex,
			&src.visibility, &src.visibleTo)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && c != nil && !c.Grants.Visible([]string{src.scope}, src.visibility, src.visibleTo) {
			return nil, refuse(404, "not-found", "source %q", b.Source)
		}
		if err != nil {
			return nil, err
		}
	}
	var tgt struct {
		id                             uuid.UUID
		revision                       int64
		scope, platformScope, platform string
		state, visibility              string
		visibleTo                      []string
		definition                     json.RawMessage
	}
	err := s.DB.QueryRow(ctx, `SELECT id, revision, scope, platform_scope, platform, state, visibility, visible_to, definition FROM targets
		WHERE name = $1 AND state <> 'RETIRED'`, b.Target).Scan(&tgt.id, &tgt.revision, &tgt.scope, &tgt.platformScope, &tgt.platform,
		&tgt.state, &tgt.visibility, &tgt.visibleTo, &tgt.definition)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && c != nil && !c.Grants.Visible([]string{tgt.scope, tgt.platformScope}, tgt.visibility, tgt.visibleTo) {
		return nil, refuse(404, "not-found", "target %q", b.Target)
	}
	if err != nil {
		return nil, err
	}
	var grants json.RawMessage
	var privileges []string
	var levelState string
	err = s.DB.QueryRow(ctx, "SELECT grants, privileges, state FROM target_access_levels WHERE target_id = $1 AND name = $2",
		tgt.id, b.AccessLevel).Scan(&grants, &privileges, &levelState)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, invalid("accessLevel %q is not a level of %s", b.AccessLevel, b.Target)
	}
	if err != nil {
		return nil, err
	}
	if consent == changerequests.ConsentAll && (cur == nil || b.AccessLevel != cur.accessLevel) {
		if src.state != "ACTIVE" || tgt.state != "ACTIVE" || levelState != "ACTIVE" {
			return nil, refuse(409, "resource-deprecated", "the source, the target and the access level must be ACTIVE")
		}
	}
	if cur == nil {
		var n int
		if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM bindings WHERE source_id = $1 AND target_id = $2", src.id, tgt.id).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, refuse(409, "binding-exists", "%s and %s are already bound", b.Source, b.Target)
		}
		if err := engine.CheckName(engine.KindBinding, b.Name, src.scope, s.Rules.NamePrefixes); err != nil {
			return nil, invalid("name: %v", err)
		}
	}
	pl, ok := s.Rules.Platforms[tgt.platform]
	if !ok {
		return nil, invalid("the platform %q of %s is not configured", tgt.platform, b.Target)
	}
	if !slices.Contains(pl.AllowedTrustDomains, src.td) {
		return nil, invalid("platform %s does not accept the trust domain %s", pl.Name, src.td)
	}
	if _, err := regexpolicy.ValidateSVIDRegex(src.regex, src.td, s.Rules.Regex); err != nil {
		return nil, invalid("the regex of %s: %v", b.Source, err)
	}
	res := &resolved{platform: pl, sourceScope: src.scope, targetScope: tgt.scope, platformScope: tgt.platformScope,
		decision: governance.Decision{Allowed: true, DistinctApprovers: p.RequireDistinctApprovers}}
	switch {
	case c != nil && consent == changerequests.ConsentAny:
		if err := res.actsFor(*c); err != nil {
			return nil, err
		}
	case c != nil:
		if !c.Grants.ActsFor(src.scope, pl.Name) && !c.Grants.ActsFor(tgt.scope, pl.Name) {
			return nil, refuse(403, "forbidden", "%s is no operator of %s or %s", c.ID(), src.scope, tgt.scope)
		}
		if res.decision = p.Evaluate(src.scope, tgt.scope); !res.decision.Allowed {
			return nil, s.denied(ctx, *c, b, res)
		}
		if err := s.Rules.checkExpiry(b.ExpiresAt, time.Now()); err != nil {
			return nil, err
		}
	}
	params := b.Parameters
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	resp, err := s.Validate(ctx, &pluginv1.ValidateBindingRequest{Instance: pl.Name, DefinitionJson: tgt.definition,
		AccessLevel: b.AccessLevel, AccessLevelGrantsJson: grants, ParametersJson: params, SourceTrustDomain: src.td})
	if err != nil {
		return nil, fmt.Errorf("bindings: ValidateBinding on %s: %w", pl.Name, err)
	}
	if !resp.GetValid() {
		return nil, invalid("%v", resp.GetErrors())
	}
	if !slices.Equal(resp.GetPrivileges(), privileges) {
		return nil, invalid("the plugin of %s returned privileges %v for the level's %v (§5.8 rule 8)", pl.Name, resp.GetPrivileges(), privileges)
	}
	b.SourceRevision, b.TargetRevision = src.revision, tgt.revision
	b.Parameters, b.RequestedSpec = resp.GetNormalizedParametersJson(), resp.GetRequestedSpecJson()
	return res, nil
}

// anySides are the sides of a change that only removes access: one for
// each of the source, target and platform scopes the requester acts for;
// equal scopes give one side, named after the first (§7.2.3).
func (res *resolved) anySides(c changerequests.Caller, breakGlass bool) []changerequests.Candidate {
	var out []changerequests.Candidate
	for _, sd := range []struct{ name, scope string }{{"SOURCE", res.sourceScope}, {"TARGET", res.targetScope}, {"PLATFORM", res.platformScope}} {
		acts := c.Grants.ActsFor(sd.scope, res.platform.Name) || breakGlass && c.Grants.BreakGlass(sd.scope)
		if acts && !slices.ContainsFunc(out, func(o changerequests.Candidate) bool { return o.Scope == sd.scope }) {
			out = append(out, changerequests.Candidate{Side: sd.name, Scope: sd.scope, Platform: res.platform.Name})
		}
	}
	return out
}

// actsFor is RBAC for a change that only removes access: operator of the
// source, target or platform scope.
func (res *resolved) actsFor(c changerequests.Caller) error {
	if len(res.anySides(c, false)) == 0 {
		return refuse(403, "forbidden", "%s is no operator of %s, %s or %s", c.ID(), res.sourceScope, res.targetScope, res.platformScope)
	}
	return nil
}

// denied audits a binding the interconnection policy refuses; nothing else
// is stored (ADR-14 rule 3).
func (s *Service) denied(ctx context.Context, c changerequests.Caller, b *Binding, res *resolved) error {
	snap, _ := json.Marshal(map[string]string{"sourceScope": res.sourceScope, "targetScope": res.targetScope, "rule": res.decision.Rule})
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceName: b.Name, Action: "CR_INTERCONNECT_DENIED",
			Actor: c.ID(), Snapshot: snap})
		return err
	})
	if err != nil {
		return err
	}
	return refuse(403, "interconnect-denied", "the interconnection policy denies %s to %s (rule %s)", res.sourceScope, res.targetScope, res.decision.Rule)
}

// file files the change request of a validated binding change with its
// sides: TARGET, SOURCE when the scopes differ, and the policy's parties
// (§7.2.3 "Sides at creation").
func (s *Service) file(ctx context.Context, c changerequests.Caller, op, consent string, cur *stored, b *Binding, res *resolved, common *changerequests.Common) (*changerequests.Request, error) {
	r, sides, err := compose(op, consent, cur, b, res, common, res.anySides(c, false))
	if err != nil {
		return nil, err
	}
	return r, pendingError(s.Requests.Create(ctx, c, r, sides, common.ApprovalReference), b.Name)
}

func pendingError(err error, name string) error {
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.ConstraintName == "uq_cr_one_pending_per_resource" {
		return refuse(409, "change-request-pending", "binding %q has a pending change request", name)
	}
	return err
}

// compose builds the change request of a validated binding change and the
// sides it needs: anySides with consent ANY; with ALL, TARGET, SOURCE when
// the scopes differ, and the policy's parties (§7.2.3 "Sides at creation").
func compose(op, consent string, cur *stored, b *Binding, res *resolved, common *changerequests.Common, anySides []changerequests.Candidate) (*changerequests.Request, []changerequests.Candidate, error) {
	payload, err := json.Marshal(b)
	if op == "DELETE" {
		payload = json.RawMessage("{}")
	}
	if err != nil {
		return nil, nil, err
	}
	r := &changerequests.Request{ResourceType: "BINDING", ResourceName: b.Name, Operation: op, Consent: consent,
		Zone: res.platform.Zone, SourceScope: res.sourceScope, TargetScope: res.targetScope, PlatformScope: res.platformScope,
		InterconnectRule: res.decision.Rule, DistinctApprovers: res.decision.DistinctApprovers, ExpectedRevision: common.ExpectedRevision,
		Payload: payload, AutomationContext: common.AutomationContext}
	if cur != nil {
		r.ResourceID = &cur.id
	}
	sides := anySides
	if consent == changerequests.ConsentAll {
		sides = []changerequests.Candidate{{Side: "TARGET", Scope: res.targetScope, Platform: res.platform.Name}}
		if res.sourceScope != res.targetScope {
			sides = append(sides, changerequests.Candidate{Side: "SOURCE", Scope: res.sourceScope, Platform: res.platform.Name})
		}
		for _, a := range res.decision.AdditionalApprovals {
			sides = append(sides, changerequests.Candidate{Side: "PARTY:" + a.Name, Scope: a.Scope, Platform: res.platform.Name})
		}
	}
	return r, sides, nil
}

// Revalidate re-runs the pipeline, plugin included, on the stored request
// (approval steps 2 and 3); the policy is re-checked by Recheck.
func (s *Service) Revalidate(ctx context.Context, r *changerequests.Request) (json.RawMessage, error) {
	var cur *stored
	if r.Operation != "CREATE" {
		var err error
		if cur, err = load(ctx, s.DB, "b.id = $1", *r.ResourceID, false); err != nil {
			return nil, err
		}
	}
	if r.Operation == "DELETE" {
		return r.Payload, nil // no plugin call, no drift check
	}
	var b Binding
	if err := json.Unmarshal(r.Payload, &b); err != nil {
		return nil, err
	}
	b.SourceRevision, b.TargetRevision, b.RequestedSpec = 0, 0, nil // derived again
	if r.Consent == changerequests.ConsentAny && !s.removesOnly(ctx, cur, &b) {
		return nil, invalid("the change no longer only removes access: file it again")
	}
	if _, err := s.resolve(ctx, nil, &b, cur, s.Requests.Policy, r.Consent, nil); err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

// Apply starts the binding's new revision (§6.2.2 step 1): the binding is
// PROVISIONING with a new workflow ID, which the sweeper starts if nothing
// else does (§6.3).
func (s *Service) Apply(ctx context.Context, tx pgx.Tx, r *changerequests.Request) ([]audit.Entry, error) {
	var b Binding
	if err := json.Unmarshal(r.Payload, &b); err != nil {
		return nil, err
	}
	var cur *stored
	if r.Operation != "CREATE" {
		var err error
		if cur, err = load(ctx, tx, "b.id = $1", *r.ResourceID, true); err != nil {
			return nil, err
		}
		switch cur.phase {
		case "PROVISIONING", "DELETING":
			return nil, refuse(409, "binding-busy", "the binding is %s", cur.phase)
		case "DELETE_FAILED":
			return nil, refuse(409, "invalid-transition", "the binding is DELETE_FAILED")
		}
		if cur.revision != *r.ExpectedRevision {
			return nil, refuse(409, "revision-conflict", "the binding is at revision %d", cur.revision)
		}
		if r.Operation == "UPDATE" && cur.breakGlassCR != nil && r.Kind != "SYSTEM_REVERT" {
			return nil, breakGlassOpen(cur)
		}
	}
	if r.Operation == "DELETE" {
		return s.applyDelete(ctx, tx, r, cur)
	}
	snap, err := lockSnapshot(ctx, tx, &b)
	if err != nil {
		return nil, err
	}
	if r.Consent == changerequests.ConsentAll && (cur == nil || b.AccessLevel != cur.accessLevel) &&
		(snap.srcState != "ACTIVE" || snap.tgtState != "ACTIVE" || snap.levelState != "ACTIVE") {
		return nil, refuse(409, "resource-deprecated", "the source, the target and the access level must be ACTIVE")
	}
	if snap.srcRev != b.SourceRevision || snap.tgtRev != b.TargetRevision {
		return nil, refuse(409, "normalization-drift", "the source or the target changed since validation: file the change again")
	}
	var id uuid.UUID
	var revision, attempt int64
	if cur == nil {
		labels := labelsJSON(b.Labels)
		pl := s.Rules.Platforms[snap.platform]
		if pl.SecretStorageStrategy == "" {
			return nil, fmt.Errorf("bindings: platform %s has no resolved secret_storage_strategy", snap.platform)
		}
		id, revision, attempt = uuid.NewV7(), 1, 1
		principal, err := engine.DerivedPrincipalName(id, pl.PrincipalPrefix)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
			identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy,
			derived_principal_name, source_scope, target_scope, platform_scope, parameters, purpose, labels, expires_at, workflow_id,
			source_revision, target_revision, source_trust_domain, source_svid_regex, requested_spec, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18::jsonb, $19, $20::jsonb, $21, $22,
			$23, $24, $25, $26, $27::jsonb, $28, $28)`,
			id, b.Name, snap.sourceID, snap.targetID, b.AccessLevel, pl.Zone, pl.Type, pl.Name, pl.IdentityProviderType, pl.IdentityProviderInstance,
			pl.SecretStoreType, pl.SecretStoreInstance, pl.SecretStorageStrategy, principal, r.SourceScope, r.TargetScope, r.PlatformScope,
			string(b.Parameters), null(b.Purpose), labels, b.ExpiresAt, workflowID(id, revision, attempt), snap.srcRev, snap.tgtRev, snap.td,
			snap.regex, string(b.RequestedSpec), r.RequestedBy)
		if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) {
			switch pe.ConstraintName {
			case "uq_binding_source_target":
				return nil, refuse(409, "binding-exists", "%s and %s are already bound", b.Source, b.Target)
			case "bindings_name_key":
				return nil, refuse(409, "invalid-transition", "a binding called %q appeared meanwhile", b.Name)
			}
		}
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, "UPDATE change_requests SET resource_id = $2 WHERE id = $1", r.ID, id); err != nil {
			return nil, err
		}
		r.ResourceID = &id
	} else {
		id = cur.id
		if revision, attempt, err = revise(ctx, tx, cur, &b, snap, r.RequestedBy); err != nil {
			return nil, err
		}
	}
	if r.Kind == changerequests.KindBreakGlass { // §6.2.2 break-glass bookkeeping
		if _, err := tx.Exec(ctx, `UPDATE bindings SET break_glass_cr_id = $2, break_glass_expires_at = now() + $3::interval,
			break_glass_warned_at = NULL WHERE id = $1`, id, r.ID, r.TTL.String()); err != nil {
			return nil, err
		}
	}
	return []audit.Entry{{ResourceType: "BINDING", ResourceID: &id, ResourceName: b.Name, ChangeRequestID: &r.ID,
		Action: "APPLY_STARTED", Revision: &revision, Attempt: &attempt, WorkflowID: workflowID(id, revision, attempt)}}, nil
}

// snapshot is the source, target and access level a revision is composed
// from, read under FOR SHARE locks (§4.3).
type snapshot struct {
	sourceID, targetID             uuid.UUID
	td, regex, platform            string
	srcState, tgtState, levelState string
	srcRev, tgtRev                 int64
}

func lockSnapshot(ctx context.Context, tx pgx.Tx, b *Binding) (*snapshot, error) {
	sn := &snapshot{}
	err := tx.QueryRow(ctx, `SELECT s.id, s.revision, s.state, s.trust_domain, s.svid_regex, t.id, t.revision, t.state, t.platform, l.state
		FROM sources s, targets t JOIN target_access_levels l ON l.target_id = t.id AND l.name = $3
		WHERE s.name = $1 AND s.state <> 'RETIRED' AND t.name = $2 AND t.state <> 'RETIRED'
		FOR SHARE OF s, t, l`, b.Source, b.Target, b.AccessLevel).Scan(&sn.sourceID, &sn.srcRev, &sn.srcState, &sn.td, &sn.regex,
		&sn.targetID, &sn.tgtRev, &sn.tgtState, &sn.platform, &sn.levelState)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refuse(409, "resource-changed", "the source, the target or the access level is gone")
	}
	return sn, err
}

// revise starts the next revision of cur, composed from b and sn
// (§6.2.2 step 3): PROVISIONING with a new attempt and workflow, rotating
// for a FAILED binding or a changed regex (§6.4). The new revision
// includes every applied change: its propagation row goes.
func revise(ctx context.Context, tx pgx.Tx, cur *stored, b *Binding, sn *snapshot, actor string) (revision, attempt int64, err error) {
	revision, attempt = cur.revision+1, cur.attempt+1
	if _, err := tx.Exec(ctx, `UPDATE bindings SET access_level = $2, parameters = $3::jsonb, purpose = $4, labels = $5::jsonb,
		expiry_warned_at = CASE WHEN expires_at IS DISTINCT FROM $6 THEN NULL ELSE expiry_warned_at END, expires_at = $6, revision = $7, attempt = $8, phase = 'PROVISIONING', operation = 'APPLY', workflow_id = $9,
		current_step = 'INIT', status_message = '', last_transition_at = now(),
		rotate_static_secrets = (phase = 'FAILED' OR source_svid_regex IS DISTINCT FROM $13),
		source_revision = $10, target_revision = $11, source_trust_domain = $12, source_svid_regex = $13, requested_spec = $14::jsonb,
		updated_at = now(), updated_by = $15 WHERE id = $1`,
		cur.id, b.AccessLevel, string(b.Parameters), null(b.Purpose), labelsJSON(b.Labels), b.ExpiresAt, revision, attempt,
		workflowID(cur.id, revision, attempt), sn.srcRev, sn.tgtRev, sn.td, sn.regex, string(b.RequestedSpec), actor); err != nil {
		return 0, 0, err
	}
	_, err = tx.Exec(ctx, "DELETE FROM binding_propagation_queue WHERE binding_id = $1", cur.id)
	return revision, attempt, err
}

func labelsJSON(l map[string]string) string {
	if l == nil {
		return "{}"
	}
	b, _ := json.Marshal(l)
	return string(b)
}

// applyDelete starts the deletion of a binding (§6.2.2, §3.11): DELETING
// with a new attempt, its active snapshot cleared at once (T-10).
func (s *Service) applyDelete(ctx context.Context, tx pgx.Tx, r *changerequests.Request, cur *stored) ([]audit.Entry, error) {
	attempt := cur.attempt + 1
	wf := fmt.Sprintf("ligo:delete:%s:r%d:a%d", cur.id, cur.revision, attempt)
	if _, err := tx.Exec(ctx, `UPDATE bindings SET phase = 'DELETING', operation = 'DELETE', attempt = $2, workflow_id = $3,
		current_step = 'INIT', status_message = '', last_transition_at = now(), active_revision = NULL,
		active_source_svid_regex = NULL, active_auth_config = NULL, active_spec = NULL, break_glass_cr_id = NULL,
		break_glass_expires_at = NULL, break_glass_warned_at = NULL, updated_at = now(), updated_by = $4 WHERE id = $1`,
		cur.id, attempt, wf, r.RequestedBy); err != nil {
		return nil, err
	}
	entries := []audit.Entry{{ResourceType: "BINDING", ResourceID: &cur.id, ResourceName: cur.name, ChangeRequestID: &r.ID,
		Action: "DELETE_STARTED", Revision: &cur.revision, Attempt: &attempt, WorkflowID: wf}}
	if r.Kind == kindExpiry {
		entries = append(entries, audit.Entry{ResourceType: "BINDING", ResourceID: &cur.id, ResourceName: cur.name, ChangeRequestID: &r.ID,
			Action: "BINDING_EXPIRED", Revision: &cur.revision})
	}
	return entries, nil
}

// workflowID is the ID of an apply attempt's workflow, never reused
// (INV-09).
func workflowID(id uuid.UUID, revision, attempt int64) string {
	return fmt.Sprintf("ligo:apply:%s:r%d:a%d", id, revision, attempt)
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}
