package bindings

import (
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
	"github.com/dihedron/ligo/internal/regexpolicy"
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
	res, err := s.resolve(ctx, &c, &b, nil, s.Requests.Policy)
	if err != nil {
		return nil, err
	}
	return s.file(ctx, c, "CREATE", nil, &b, res, &req.Common)
}

// Update files a change of a binding that adds access, or changes it
// otherwise (PUT /v1/admin/bindings/{name}): consent ALL.
func (s *Service) Update(ctx context.Context, c changerequests.Caller, name string, body []byte) (*changerequests.Request, error) {
	req, err := decode(body)
	if err != nil {
		return nil, err
	}
	if req.ExpectedRevision == nil {
		return nil, invalid("expectedRevision is required")
	}
	cur, err := load(ctx, s.DB, "b.name = $1", name, false)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Grants.Sees(cur.sourceScope, cur.targetScope, cur.platformScope) {
		return nil, refuse(404, "not-found", "binding %q", name)
	}
	if err != nil {
		return nil, err
	}
	b := req.Binding
	if b.Name == "" {
		b.Name = name
	}
	res, err := s.resolve(ctx, &c, &b, cur, s.Requests.Policy)
	if err != nil {
		return nil, err
	}
	if *req.ExpectedRevision != cur.revision {
		return nil, refuse(409, "revision-conflict", "the binding is at revision %d", cur.revision)
	}
	return s.file(ctx, c, "UPDATE", cur, &b, res, &req.Common)
}

// stored is the part of a binding row its changes need.
type stored struct {
	id                                      uuid.UUID
	name, source, target, accessLevel       string
	sourceScope, targetScope, platformScope string
	phase                                   string
	revision, attempt                       int64
}

func load(ctx context.Context, q store.Querier, where string, arg any, lock bool) (*stored, error) {
	st := &stored{}
	sql := `SELECT b.id, b.name, s.name, t.name, b.access_level, b.source_scope, b.target_scope, b.platform_scope, b.phase,
		b.revision, b.attempt FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id WHERE ` + where
	if lock {
		sql += " FOR UPDATE OF b"
	}
	err := q.QueryRow(ctx, sql, arg).Scan(&st.id, &st.name, &st.source, &st.target, &st.accessLevel, &st.sourceScope,
		&st.targetScope, &st.platformScope, &st.phase, &st.revision, &st.attempt)
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
// checked by the approval itself (Recheck).
func (s *Service) resolve(ctx context.Context, c *changerequests.Caller, b *Binding, cur *stored, p *governance.Policy) (*resolved, error) {
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
	err := s.DB.QueryRow(ctx, `SELECT id, revision, scope, state, trust_domain, svid_regex, visibility, visible_to FROM sources
		WHERE name = $1 AND state <> 'RETIRED'`, b.Source).Scan(&src.id, &src.revision, &src.scope, &src.state, &src.td, &src.regex,
		&src.visibility, &src.visibleTo)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && c != nil && !c.Grants.Visible([]string{src.scope}, src.visibility, src.visibleTo) {
		return nil, refuse(404, "not-found", "source %q", b.Source)
	}
	if err != nil {
		return nil, err
	}
	var tgt struct {
		id                             uuid.UUID
		revision                       int64
		scope, platformScope, platform string
		state, visibility              string
		visibleTo                      []string
		definition                     json.RawMessage
	}
	err = s.DB.QueryRow(ctx, `SELECT id, revision, scope, platform_scope, platform, state, visibility, visible_to, definition FROM targets
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
	if cur == nil || b.AccessLevel != cur.accessLevel {
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
	if c != nil {
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
func (s *Service) file(ctx context.Context, c changerequests.Caller, op string, cur *stored, b *Binding, res *resolved, common *changerequests.Common) (*changerequests.Request, error) {
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	r := &changerequests.Request{ResourceType: "BINDING", ResourceName: b.Name, Operation: op, Consent: changerequests.ConsentAll,
		Zone: res.platform.Zone, SourceScope: res.sourceScope, TargetScope: res.targetScope, PlatformScope: res.platformScope,
		InterconnectRule: res.decision.Rule, DistinctApprovers: res.decision.DistinctApprovers, ExpectedRevision: common.ExpectedRevision,
		Payload: payload, AutomationContext: common.AutomationContext}
	if cur != nil {
		r.ResourceID = &cur.id
	}
	sides := []changerequests.Candidate{{Side: "TARGET", Scope: res.targetScope, Platform: res.platform.Name}}
	if res.sourceScope != res.targetScope {
		sides = append(sides, changerequests.Candidate{Side: "SOURCE", Scope: res.sourceScope, Platform: res.platform.Name})
	}
	for _, a := range res.decision.AdditionalApprovals {
		sides = append(sides, changerequests.Candidate{Side: "PARTY:" + a.Name, Scope: a.Scope, Platform: res.platform.Name})
	}
	err = s.Requests.Create(ctx, c, r, sides, common.ApprovalReference)
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.ConstraintName == "uq_cr_one_pending_per_resource" {
		return nil, refuse(409, "change-request-pending", "binding %q has a pending change request", b.Name)
	}
	return r, err
}

// Revalidate re-runs the pipeline, plugin included, on the stored request
// (approval steps 2 and 3); the policy is re-checked by Recheck.
func (s *Service) Revalidate(ctx context.Context, r *changerequests.Request) (json.RawMessage, error) {
	var b Binding
	if err := json.Unmarshal(r.Payload, &b); err != nil {
		return nil, err
	}
	b.SourceRevision, b.TargetRevision, b.RequestedSpec = 0, 0, nil // derived again
	var cur *stored
	if r.Operation == "UPDATE" {
		var err error
		if cur, err = load(ctx, s.DB, "b.id = $1", *r.ResourceID, false); err != nil {
			return nil, err
		}
	}
	if _, err := s.resolve(ctx, nil, &b, cur, s.Requests.Policy); err != nil {
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
	if r.Operation == "UPDATE" {
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
	}
	var sourceID, targetID uuid.UUID
	var td, regex, platform, srcState, tgtState, levelState string
	var srcRev, tgtRev int64
	err := tx.QueryRow(ctx, `SELECT s.id, s.revision, s.state, s.trust_domain, s.svid_regex, t.id, t.revision, t.state, t.platform, l.state
		FROM sources s, targets t JOIN target_access_levels l ON l.target_id = t.id AND l.name = $3
		WHERE s.name = $1 AND s.state <> 'RETIRED' AND t.name = $2 AND t.state <> 'RETIRED'
		FOR SHARE OF s, t, l`, b.Source, b.Target, b.AccessLevel).Scan(&sourceID, &srcRev, &srcState, &td, &regex, &targetID, &tgtRev,
		&tgtState, &platform, &levelState)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refuse(409, "resource-changed", "the source, the target or the access level is gone")
	}
	if err != nil {
		return nil, err
	}
	if (cur == nil || b.AccessLevel != cur.accessLevel) && (srcState != "ACTIVE" || tgtState != "ACTIVE" || levelState != "ACTIVE") {
		return nil, refuse(409, "resource-deprecated", "the source, the target and the access level must be ACTIVE")
	}
	if srcRev != b.SourceRevision || tgtRev != b.TargetRevision {
		return nil, refuse(409, "normalization-drift", "the source or the target changed since validation: file the change again")
	}
	labels, _ := json.Marshal(b.Labels)
	if b.Labels == nil {
		labels = []byte("{}")
	}
	var id uuid.UUID
	var revision, attempt int64
	if cur == nil {
		pl := s.Rules.Platforms[platform]
		if pl.SecretStorageStrategy == "" {
			return nil, fmt.Errorf("bindings: platform %s has no resolved secret_storage_strategy", platform)
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
			id, b.Name, sourceID, targetID, b.AccessLevel, pl.Zone, pl.Type, pl.Name, pl.IdentityProviderType, pl.IdentityProviderInstance,
			pl.SecretStoreType, pl.SecretStoreInstance, pl.SecretStorageStrategy, principal, r.SourceScope, r.TargetScope, r.PlatformScope,
			string(b.Parameters), null(b.Purpose), string(labels), b.ExpiresAt, workflowID(id, revision, attempt), srcRev, tgtRev, td, regex,
			string(b.RequestedSpec), r.RequestedBy)
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
		id, revision, attempt = cur.id, cur.revision+1, cur.attempt+1
		if _, err := tx.Exec(ctx, `UPDATE bindings SET access_level = $2, parameters = $3::jsonb, purpose = $4, labels = $5::jsonb,
			expires_at = $6, revision = $7, attempt = $8, phase = 'PROVISIONING', operation = 'APPLY', workflow_id = $9,
			current_step = 'INIT', status_message = '', last_transition_at = now(), rotate_static_secrets = false,
			source_revision = $10, target_revision = $11, source_trust_domain = $12, source_svid_regex = $13, requested_spec = $14::jsonb,
			updated_at = now(), updated_by = $15 WHERE id = $1`,
			id, b.AccessLevel, string(b.Parameters), null(b.Purpose), string(labels), b.ExpiresAt, revision, attempt,
			workflowID(id, revision, attempt), srcRev, tgtRev, td, regex, string(b.RequestedSpec), r.RequestedBy); err != nil {
			return nil, err
		}
		// the new revision includes every applied change (§6.2.2)
		if _, err := tx.Exec(ctx, "DELETE FROM binding_propagation_queue WHERE binding_id = $1", id); err != nil {
			return nil, err
		}
	}
	return []audit.Entry{{ResourceType: "BINDING", ResourceID: &id, ResourceName: b.Name, ChangeRequestID: &r.ID,
		Action: "APPLY_STARTED", Revision: &revision, Attempt: &attempt, WorkflowID: workflowID(id, revision, attempt)}}, nil
}

// workflowID is the ID of an attempt's workflow, never reused (INV-09).
func workflowID(id uuid.UUID, revision, attempt int64) string {
	return fmt.Sprintf("ligo:apply:%s:r%d:a%d", id, revision, attempt)
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}
