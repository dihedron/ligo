package targets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service files the change requests of targets, and is their
// changerequests.Resource.
type Service struct {
	DB       *pgxpool.Pool // the app pool
	Rules    *Rules
	Requests *changerequests.Service
	Validate ValidateTarget
}

// Plugins calls ValidateTarget through the plugin manager.
func Plugins(m *pluginmgr.Manager) ValidateTarget {
	return func(ctx context.Context, req *pluginv1.ValidateTargetRequest) (resp *pluginv1.ValidateTargetResponse, err error) {
		err = m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, req.GetInstance(), false, func(ctx context.Context, c *pluginmgr.Client) error {
			resp, err = c.Platform.ValidateTarget(ctx, req)
			return err
		})
		return resp, err
	}
}

// request is the body of a create (§7.2.3).
type request struct {
	Target
	changerequests.Common
}

// Create files the publication of a target (POST /v1/admin/targets).
func (s *Service) Create(ctx context.Context, c changerequests.Caller, body []byte) (*changerequests.Request, error) {
	var req request
	if err := changerequests.Decode(body, &req, &req.Common); err != nil {
		return nil, err
	}
	if req.ExpectedRevision != nil {
		return nil, invalid("expectedRevision is only for updates")
	}
	t := req.Target
	var n int
	if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM targets WHERE name = $1 AND state <> 'RETIRED'", t.Metadata.Name).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, invalid("metadata.name %q is in use", t.Metadata.Name)
	}
	authorize := func(t *Target) error {
		if m := t.Metadata; !c.Grants.ActsFor(m.Scope, m.Platform) && !c.Grants.ActsFor(m.PlatformScope, m.Platform) {
			return refuse(403, "forbidden", "%s is no operator of %s or %s", c.ID(), m.Scope, m.PlatformScope)
		}
		return nil
	}
	if err := s.Rules.validate(ctx, s.Validate, &t, authorize); err != nil {
		return nil, err
	}
	return s.file(ctx, c, "CREATE", &t, &req.Common)
}

// file files the change request of a validated target change: an OWNER
// side, and a PLATFORM side unless the two scopes are equal.
func (s *Service) file(ctx context.Context, c changerequests.Caller, op string, t *Target, common *changerequests.Common) (*changerequests.Request, error) {
	payload, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	m := t.Metadata
	r := &changerequests.Request{ResourceType: "TARGET", ResourceName: m.Name, Operation: op, Consent: changerequests.ConsentAll,
		Zone: m.Zone, OwnerScope: m.Scope, PlatformScope: m.PlatformScope, ExpectedRevision: common.ExpectedRevision,
		Payload: payload, AutomationContext: common.AutomationContext}
	sides := []changerequests.Candidate{{Side: "OWNER", Scope: m.Scope, Platform: m.Platform}}
	if m.PlatformScope != m.Scope {
		sides = append(sides, changerequests.Candidate{Side: "PLATFORM", Scope: m.PlatformScope, Platform: m.Platform})
	}
	err = s.Requests.Create(ctx, c, r, sides, common.ApprovalReference)
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.ConstraintName == "uq_cr_one_pending_per_resource" {
		return nil, refuse(409, "change-request-pending", "target %q has a pending change request", m.Name)
	}
	return r, err
}

// payload decodes a stored request's payload without the fields the
// pipeline derives again.
func payload(r *changerequests.Request) (*Target, error) {
	var t Target
	if err := json.Unmarshal(r.Payload, &t); err != nil {
		return nil, err
	}
	m := &t.Metadata
	m.PlatformType, m.PlatformScope, m.Zone, m.State = "", "", "", ""
	for i := range t.AccessLevels {
		t.AccessLevels[i].Privileges, t.AccessLevels[i].State = nil, ""
	}
	return &t, nil
}

// Revalidate re-runs the pipeline, plugin included, on the stored request
// (approval steps 2 and 3).
func (s *Service) Revalidate(ctx context.Context, r *changerequests.Request) (json.RawMessage, error) {
	t, err := payload(r)
	if err != nil {
		return nil, err
	}
	if err := s.Rules.validate(ctx, s.Validate, t, nil); err != nil {
		return nil, err
	}
	return json.Marshal(t)
}

// Apply writes an approved change (§6.2.1 steps 2 to 5).
func (s *Service) Apply(ctx context.Context, tx pgx.Tx, r *changerequests.Request) ([]audit.Entry, error) {
	var t Target
	if err := json.Unmarshal(r.Payload, &t); err != nil {
		return nil, err
	}
	if r.Operation != "CREATE" {
		return nil, fmt.Errorf("targets: %s is not supported yet", r.Operation)
	}
	id := uuid.NewV7()
	if err := insert(ctx, tx, id, &t, r.RequestedBy); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "UPDATE change_requests SET resource_id = $2 WHERE id = $1", r.ID, id); err != nil {
		return nil, err
	}
	r.ResourceID = &id
	revision := int64(1)
	return []audit.Entry{{ResourceType: "TARGET", ResourceID: &id, ResourceName: r.ResourceName, ChangeRequestID: &r.ID,
		Action: "TARGET_PUBLISHED", Revision: &revision}}, nil
}

// jsonb is v as JSON, or empty (an empty object or array) when v is nil.
func jsonb(v any, empty string) string {
	data, err := json.Marshal(v)
	if err != nil || string(data) == "null" {
		return empty
	}
	return string(data)
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// multirange is ports as an int4multirange literal: inclusive ranges become
// half-open ones.
func multirange(f *pluginv1.NetworkFlow) string {
	var parts []string
	for _, p := range f.GetPorts() {
		parts = append(parts, fmt.Sprintf("[%d,%d)", p.GetLow(), p.GetHigh()+1))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func insert(ctx context.Context, tx pgx.Tx, id uuid.UUID, t *Target, actor string) error {
	m := t.Metadata
	_, err := tx.Exec(ctx, `INSERT INTO targets (id, name, platform, platform_type, zone, scope, platform_scope, definition,
		display_name, description, labels, documentation_url, contacts, visibility, visible_to, state, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11::jsonb, $12, $13::jsonb, $14, $15::jsonb, 'ACTIVE', $16, $16)`,
		id, m.Name, m.Platform, m.PlatformType, m.Zone, m.Scope, m.PlatformScope, string(t.Definition), null(t.DisplayName),
		null(t.Description), jsonb(t.Labels, "{}"), null(t.DocumentationURL), jsonb(t.Contacts, "[]"), t.Visibility.Mode,
		jsonb(t.Visibility.VisibleTo, "[]"), actor)
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.ConstraintName == "uq_targets_name" {
		return invalid("metadata.name %q is in use", m.Name)
	}
	if err != nil {
		return err
	}
	for _, l := range t.AccessLevels {
		if _, err := tx.Exec(ctx, `INSERT INTO target_access_levels (target_id, name, description, grants, privileges, state)
			VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)`, id, l.Name, null(l.Description), string(l.Grants),
			jsonb(l.Privileges, "[]"), l.State); err != nil {
			return err
		}
	}
	for _, f := range t.NetworkFlows {
		pf := toProto(f)
		if _, err := tx.Exec(ctx, `INSERT INTO target_network_flows (target_id, name, purpose, protocol, destination, ports,
			tls, server_name, description) VALUES ($1, $2, $3, $4, $5, $6::int4multirange, $7, $8, $9)`,
			id, f.Name, f.Purpose, f.Protocol, f.Destination, multirange(pf), f.TLS, null(f.ServerName), null(f.Description)); err != nil {
			return err
		}
	}
	return nil
}
