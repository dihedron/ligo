package bindings

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/jackc/pgx/v5"
)

// View is the admin representation of a binding (§3.5).
type View struct {
	APIVersion  string            `json:"apiVersion"`
	Kind        string            `json:"kind"`
	Metadata    ViewMetadata      `json:"metadata"`
	Source      string            `json:"source"`
	Target      string            `json:"target"`
	AccessLevel string            `json:"accessLevel"`
	Parameters  json.RawMessage   `json:"parameters"`
	Purpose     string            `json:"purpose,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	ExpiresAt   *time.Time        `json:"expiresAt"`
	Status      ViewStatus        `json:"status"`
	Requested   struct {
		SourceRevision int64           `json:"sourceRevision"`
		TargetRevision int64           `json:"targetRevision"`
		TrustDomain    string          `json:"trustDomain"`
		SVIDRegex      string          `json:"svidRegex"`
		Spec           json.RawMessage `json:"spec"`
	} `json:"requested"`
	Active *ViewActive     `json:"active"`
	Auth   json.RawMessage `json:"auth"`
	Spec   json.RawMessage `json:"spec"`

	partyScopes []string
}

type ViewMetadata struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Zone          string    `json:"zone"`
	SourceScope   string    `json:"sourceScope"`
	TargetScope   string    `json:"targetScope"`
	PlatformScope string    `json:"platformScope"`
	PlatformType  string    `json:"platformType"`
	Platform      string    `json:"platform"`
	Wiring        struct {
		IdentityProvider Instance `json:"identityProvider"`
		SecretStore      Instance `json:"secretStore"`
	} `json:"wiring"`
	Revision       int64     `json:"revision"`
	ActiveRevision *int64    `json:"activeRevision"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	CreatedBy      string    `json:"createdBy"`
	UpdatedBy      string    `json:"updatedBy"`
}

type Instance struct {
	Type     string `json:"type"`
	Instance string `json:"instance"`
}

type ViewStatus struct {
	Phase                  string            `json:"phase"`
	Operation              string            `json:"operation"`
	Attempt                int64             `json:"attempt"`
	WorkflowID             string            `json:"workflowId"`
	CurrentStep            string            `json:"currentStep"`
	Message                string            `json:"message"`
	LastTransitionTime     time.Time         `json:"lastTransitionTime"`
	PendingChangeRequestID *uuid.UUID        `json:"pendingChangeRequestId"`
	PropagationPending     bool              `json:"propagationPending"`
	BreakGlass             *BreakGlassStatus `json:"breakGlass"`
}

// BreakGlassStatus is the open break-glass change of a binding (§3.5).
type BreakGlassStatus struct {
	ChangeRequestID   uuid.UUID `json:"changeRequestId"`
	RequestedBy       string    `json:"requestedBy"`
	IncidentReference string    `json:"incidentReference"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

type ViewActive struct {
	Revision  int64     `json:"revision"`
	SVIDRegex string    `json:"svidRegex"`
	Since     time.Time `json:"since"`
}

const viewQuery = `SELECT b.id, b.name, b.zone, b.source_scope, b.target_scope, b.platform_scope, b.platform_type, b.platform,
	b.identity_provider_type, b.identity_provider_instance, b.secret_store_type, b.secret_store_instance, b.revision, b.active_revision,
	b.created_at, b.updated_at, b.created_by, b.updated_by, s.name, t.name, b.access_level, b.parameters, coalesce(b.purpose, ''),
	b.labels, b.expires_at, b.phase, b.operation, b.attempt, b.workflow_id, b.current_step, b.status_message, b.last_transition_at,
	(SELECT c.id FROM change_requests c WHERE c.resource_type = 'BINDING' AND c.resource_name = b.name AND c.status = 'PENDING'),
	EXISTS (SELECT 1 FROM binding_propagation_queue q WHERE q.binding_id = b.id),
	b.break_glass_cr_id, coalesce(g.requested_by, ''), coalesce(g.external_approval_ref, ''), b.break_glass_expires_at,
	b.source_revision, b.target_revision, b.source_trust_domain, b.source_svid_regex, b.requested_spec,
	coalesce(b.active_source_svid_regex, ''), b.active_since, b.active_auth_config, b.active_spec,
	coalesce((SELECT array_agg(DISTINCT sd.scope) FROM change_requests cr JOIN change_request_sides sd ON sd.change_request_id = cr.id
		WHERE cr.resource_type = 'BINDING' AND cr.resource_id = b.id AND sd.side LIKE 'PARTY:%'), '{}')
	FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id
	LEFT JOIN change_requests g ON g.id = b.break_glass_cr_id`

func scanView(row pgx.Row) (*View, error) {
	v := &View{APIVersion: sources.APIVersion, Kind: "Binding"}
	m, st := &v.Metadata, &v.Status
	var bg *uuid.UUID
	var bgBy, bgRef, activeRegex string
	var bgExpires, since *time.Time
	err := row.Scan(&m.ID, &m.Name, &m.Zone, &m.SourceScope, &m.TargetScope, &m.PlatformScope, &m.PlatformType, &m.Platform,
		&m.Wiring.IdentityProvider.Type, &m.Wiring.IdentityProvider.Instance, &m.Wiring.SecretStore.Type, &m.Wiring.SecretStore.Instance,
		&m.Revision, &m.ActiveRevision, &m.CreatedAt, &m.UpdatedAt, &m.CreatedBy, &m.UpdatedBy, &v.Source, &v.Target, &v.AccessLevel,
		&v.Parameters, &v.Purpose, &v.Labels, &v.ExpiresAt, &st.Phase, &st.Operation, &st.Attempt, &st.WorkflowID, &st.CurrentStep,
		&st.Message, &st.LastTransitionTime, &st.PendingChangeRequestID, &st.PropagationPending, &bg, &bgBy, &bgRef, &bgExpires,
		&v.Requested.SourceRevision, &v.Requested.TargetRevision, &v.Requested.TrustDomain, &v.Requested.SVIDRegex, &v.Requested.Spec,
		&activeRegex, &since, &v.Auth, &v.Spec, &v.partyScopes)
	if bg != nil && bgExpires != nil {
		st.BreakGlass = &BreakGlassStatus{ChangeRequestID: *bg, RequestedBy: bgBy, IncidentReference: bgRef, ExpiresAt: *bgExpires}
	}
	if m.ActiveRevision != nil && since != nil {
		v.Active = &ViewActive{Revision: *m.ActiveRevision, SVIDRegex: activeRegex, Since: *since}
	}
	return v, err
}

// visibleTo: a role on any of the binding's scopes, or on the scope of one
// of its additional parties (§7.2.4).
func (v *View) visibleTo(c changerequests.Caller) bool {
	m := v.Metadata
	return c.Grants.Sees(append([]string{m.SourceScope, m.TargetScope, m.PlatformScope}, v.partyScopes...)...)
}

// Get returns the binding called name if the caller sees it (404
// otherwise).
func (s *Service) Get(ctx context.Context, c changerequests.Caller, name string) (*View, error) {
	v, err := scanView(s.DB.QueryRow(ctx, viewQuery+" WHERE b.name = $1", name))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !v.visibleTo(c) {
		return nil, refuse(404, "not-found", "binding %q", name)
	}
	return v, err
}

// Filter selects bindings (GET /v1/admin/bindings).
type Filter struct {
	Source, Target, AccessLevel, Platform, PlatformType, Phase, TrustDomain, Zone string
	Scope                                                                         string     // a pattern matched against the three scopes
	ExpiringBefore                                                                *time.Time // expires_at before it
	PropagationPending                                                            *bool
	After                                                                         string
	Limit                                                                         int
}

// List returns the bindings the caller sees that f selects, by name, at
// most f.Limit, and whether more follow (keyset on name, §7.2.3).
func (s *Service) List(ctx context.Context, c changerequests.Caller, f Filter) ([]*View, bool, error) {
	var out []*View
	after := f.After
	for {
		rows, err := s.DB.Query(ctx, viewQuery+` WHERE b.name > $1 AND ($2 = '' OR s.name = $2) AND ($3 = '' OR t.name = $3)
			AND ($4 = '' OR b.access_level = $4) AND ($5 = '' OR b.platform = $5) AND ($6 = '' OR b.platform_type = $6)
			AND ($7 = '' OR b.phase::text = $7) AND ($8 = '' OR b.source_trust_domain = $8) AND ($9 = '' OR b.zone = $9)
			AND ($10::timestamptz IS NULL OR b.expires_at < $10)
			AND ($11::boolean IS NULL OR $11 = EXISTS (SELECT 1 FROM binding_propagation_queue q WHERE q.binding_id = b.id))
			ORDER BY b.name LIMIT $12`, after, f.Source, f.Target, f.AccessLevel, f.Platform, f.PlatformType, f.Phase, f.TrustDomain,
			f.Zone, f.ExpiringBefore, f.PropagationPending, 2*f.Limit)
		if err != nil {
			return nil, false, err
		}
		read := 0
		for rows.Next() {
			v, err := scanView(rows)
			if err != nil {
				rows.Close()
				return nil, false, err
			}
			read++
			after = v.Metadata.Name
			m := v.Metadata
			if !v.visibleTo(c) || f.Scope != "" && !governance.ScopeMatches(f.Scope, m.SourceScope) &&
				!governance.ScopeMatches(f.Scope, m.TargetScope) && !governance.ScopeMatches(f.Scope, m.PlatformScope) {
				continue
			}
			if len(out) == f.Limit {
				rows.Close()
				return out, true, nil
			}
			out = append(out, v)
		}
		if err := rows.Err(); err != nil {
			return nil, false, err
		}
		if read < 2*f.Limit {
			return out, false, nil
		}
	}
}

// Stage is a stage of a binding's pipeline, without secrets: its artifact
// holds no static secret (sealed apart, ADR-07).
type Stage struct {
	Stage            string          `json:"stage"`
	ProviderType     string          `json:"providerType"`
	ProviderInstance string          `json:"providerInstance"`
	Status           string          `json:"status"`
	Revision         int64           `json:"revision"`
	WorkflowID       string          `json:"workflowId"`
	Artifact         json.RawMessage `json:"artifact"`
	UpdatedAt        time.Time       `json:"updatedAt"`
}

// Stages returns the stage rows of the binding v.
func (s *Service) Stages(ctx context.Context, v *View) ([]Stage, error) {
	rows, err := s.DB.Query(ctx, `SELECT stage, provider_type, provider_instance, status, revision, workflow_id, artifact, updated_at
		FROM binding_stage_state WHERE binding_id = $1 ORDER BY stage`, v.Metadata.ID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Stage, error) {
		var st Stage
		return st, r.Scan(&st.Stage, &st.ProviderType, &st.ProviderInstance, &st.Status, &st.Revision, &st.WorkflowID, &st.Artifact, &st.UpdatedAt)
	})
	if out == nil {
		out = []Stage{}
	}
	return out, err
}

// Flows returns the effective network flows of the binding v (§3.6,
// ADR-16): its target's, its platform's, its secret store's and ligo's.
func (s *Service) Flows(ctx context.Context, v *View) ([]flows.Flow, error) {
	rows, err := s.DB.Query(ctx, `SELECT f.name, f.purpose, f.protocol, f.destination, f.ports::text, f.tls, coalesce(f.server_name, ''),
		coalesce(f.description, '') FROM target_network_flows f JOIN bindings b ON b.target_id = f.target_id WHERE b.id = $1`, v.Metadata.ID)
	if err != nil {
		return nil, err
	}
	target, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (flows.Flow, error) {
		var f flows.Flow
		var ports string
		if err := row.Scan(&f.Name, &f.Purpose, &f.Protocol, &f.Destination, &ports, &f.TLS, &f.ServerName, &f.Description); err != nil {
			return f, err
		}
		f.Ports, err = flows.ParseMultirange(ports)
		return f, err
	})
	if err != nil {
		return nil, err
	}
	m := v.Metadata
	store := m.Wiring.SecretStore.Instance
	return flows.Effective(v.Target, target, m.Platform, s.Rules.PlatformFlows[m.Platform], store, s.Rules.StoreFlows[store], s.Rules.Ligo), nil
}

// Diff compares an UPDATE's payload with the binding's current desired
// state.
func (s *Service) Diff(ctx context.Context, r *changerequests.Request) (any, error) {
	cur, err := load(ctx, s.DB, "b.id = $1", *r.ResourceID, false)
	if err != nil {
		return nil, err
	}
	old, err := json.Marshal(Binding{Kind: "Binding", Name: cur.name, Source: cur.source, Target: cur.target, AccessLevel: cur.accessLevel,
		Parameters: cur.parameters, Purpose: cur.purpose, Labels: cur.labels, ExpiresAt: cur.expiresAt})
	if err != nil {
		return nil, err
	}
	var proposed map[string]json.RawMessage
	if err := json.Unmarshal(r.Payload, &proposed); err != nil {
		return nil, err
	}
	for _, derived := range []string{"sourceRevision", "targetRevision", "requestedSpec"} { // composed at apply, not chosen
		delete(proposed, derived)
	}
	trimmed, _ := json.Marshal(proposed)
	changes, err := changerequests.Diff(old, trimmed)
	return map[string]any{"changes": changes}, err
}
