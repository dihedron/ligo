package targets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/jcs"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/store"
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

// request is the body of a create or an update (§7.2.3).
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
	if err := s.Rules.validate(ctx, s.Validate, &t, nil, authorize(c)); err != nil {
		return nil, err
	}
	return s.file(ctx, c, "CREATE", nil, &t, &req.Common, true)
}

// authorize is RBAC on a target: operator of its scope or of its platform's
// (§7.2.3 step 4).
func authorize(c changerequests.Caller) func(*Target) error {
	return func(t *Target) error {
		if m := t.Metadata; !c.Grants.ActsFor(m.Scope, m.Platform) && !c.Grants.ActsFor(m.PlatformScope, m.Platform) {
			return refuse(403, "forbidden", "%s is no operator of %s or %s", c.ID(), m.Scope, m.PlatformScope)
		}
		return nil
	}
}

// Update files a change of a target (PUT /v1/admin/targets/{name}).
func (s *Service) Update(ctx context.Context, c changerequests.Caller, name string, body []byte) (*changerequests.Request, error) {
	var req request
	if err := changerequests.Decode(body, &req, &req.Common); err != nil {
		return nil, err
	}
	if req.ExpectedRevision == nil {
		return nil, invalid("expectedRevision is required")
	}
	cur, err := s.current(ctx, c, name)
	if err != nil {
		return nil, err
	}
	t := req.Target
	if t.Metadata.Name == "" {
		t.Metadata.Name = name
	}
	return s.update(ctx, c, cur, &t, &req.Common)
}

// SetState files a deprecation, a reactivation or a retirement of a target
// (POST /v1/admin/targets/{name}/deprecate, /reactivate, /retire).
func (s *Service) SetState(ctx context.Context, c changerequests.Caller, name, op string, expectedRevision int64, approvalReference string, automationContext json.RawMessage) (*changerequests.Request, error) {
	return s.setState(ctx, c, name, "", op, &changerequests.Common{ExpectedRevision: &expectedRevision, ApprovalReference: approvalReference, AutomationContext: automationContext})
}

// SetLevelState does the same for an access level (POST
// /v1/admin/targets/{name}/access-levels/{level}/deprecate, ...).
func (s *Service) SetLevelState(ctx context.Context, c changerequests.Caller, name, level, op string, expectedRevision int64, approvalReference string, automationContext json.RawMessage) (*changerequests.Request, error) {
	return s.setState(ctx, c, name, level, op, &changerequests.Common{ExpectedRevision: &expectedRevision, ApprovalReference: approvalReference, AutomationContext: automationContext})
}

func (s *Service) setState(ctx context.Context, c changerequests.Caller, name, lvl, op string, common *changerequests.Common) (*changerequests.Request, error) {
	to, ok := map[string]string{"deprecate": "DEPRECATED", "reactivate": "ACTIVE", "retire": "RETIRED"}[op]
	if !ok {
		return nil, fmt.Errorf("targets: unknown operation %q", op)
	}
	cur, err := s.current(ctx, c, name)
	if err != nil {
		return nil, err
	}
	t := cur.Target
	t.AccessLevels = slices.Clone(cur.AccessLevels)
	for i := range t.AccessLevels {
		t.AccessLevels[i].Privileges = nil // output only
	}
	state := &t.Metadata.State
	if lvl != "" {
		l := level(&t, lvl)
		if l == nil {
			return nil, refuse(404, "not-found", "access level %q of target %q", lvl, name)
		}
		state = &l.State
	}
	if *state == to {
		return nil, refuse(409, "invalid-transition", "the state is already %s", to)
	}
	*state = to
	return s.update(ctx, c, cur, &t, common)
}

func (s *Service) update(ctx context.Context, c changerequests.Caller, cur *stored, t *Target, common *changerequests.Common) (*changerequests.Request, error) {
	if err := s.Rules.validate(ctx, s.Validate, t, &cur.Target, authorize(c)); err != nil {
		return nil, err
	}
	if err := retirable(ctx, s.DB, cur, t); err != nil {
		return nil, err
	}
	if *common.ExpectedRevision != cur.Revision {
		return nil, refuse(409, "revision-conflict", "the target is at revision %d", cur.Revision)
	}
	return s.file(ctx, c, "UPDATE", cur, t, common, material(&cur.Target, t))
}

// retirable refuses to retire a target, or a level, that bindings use.
func retirable(ctx context.Context, q store.Querier, cur *stored, t *Target) error {
	check := func(what, level string) error {
		var n int
		if err := q.QueryRow(ctx, "SELECT count(*) FROM bindings WHERE target_id = $1 AND ($2 = '' OR access_level = $2)", cur.ID, level).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return refuse(409, "resource-in-use", "%s has %d bindings", what, n)
		}
		return nil
	}
	if t.Metadata.State == "RETIRED" && cur.Metadata.State != "RETIRED" {
		if err := check("the target", ""); err != nil {
			return err
		}
	}
	for _, l := range t.AccessLevels {
		if c := level(&cur.Target, l.Name); l.State == "RETIRED" && c != nil && c.State != "RETIRED" {
			if err := check("access level "+l.Name, l.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// current reads a target the caller can see by name (404 otherwise).
func (s *Service) current(ctx context.Context, c changerequests.Caller, name string) (*stored, error) {
	cur, err := load(ctx, s.DB, "name = $1 AND state <> 'RETIRED'", name, false)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Grants.Sees(cur.Metadata.Scope, cur.Metadata.PlatformScope) {
		return nil, refuse(404, "not-found", "target %q", name)
	}
	return cur, err
}

// file files the change request of a validated target change: an OWNER
// side, and a PLATFORM side for a material change unless the two scopes
// are equal (§3.7).
func (s *Service) file(ctx context.Context, c changerequests.Caller, op string, cur *stored, t *Target, common *changerequests.Common, material bool) (*changerequests.Request, error) {
	payload, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	m := t.Metadata
	r := &changerequests.Request{ResourceType: "TARGET", ResourceName: m.Name, Operation: op, Consent: changerequests.ConsentAll,
		Zone: m.Zone, OwnerScope: m.Scope, PlatformScope: m.PlatformScope, ExpectedRevision: common.ExpectedRevision,
		Payload: payload, AutomationContext: common.AutomationContext}
	if cur != nil {
		r.ResourceID = &cur.ID
	}
	sides := []changerequests.Candidate{{Side: "OWNER", Scope: m.Scope, Platform: m.Platform}}
	if material && m.PlatformScope != m.Scope {
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
	for i := range t.AccessLevels {
		t.AccessLevels[i].Privileges = nil // output only
	}
	if r.Operation == "CREATE" { // derived again
		m := &t.Metadata
		m.PlatformType, m.PlatformScope, m.Zone, m.State = "", "", "", ""
		for i := range t.AccessLevels {
			t.AccessLevels[i].State = ""
		}
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
	var cur *Target
	if r.Operation == "UPDATE" {
		st, err := load(ctx, s.DB, "id = $1", *r.ResourceID, false)
		if err != nil {
			return nil, err
		}
		cur = &st.Target
	}
	if err := s.Rules.validate(ctx, s.Validate, t, cur, nil); err != nil {
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
	if r.Operation == "UPDATE" {
		return s.applyUpdate(ctx, tx, r, &t)
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
	return putLevelsAndFlows(ctx, tx, id, t)
}

// putLevelsAndFlows upserts the access levels of a target and replaces its
// flows (§6.2.1 step 4).
func putLevelsAndFlows(ctx context.Context, tx pgx.Tx, id uuid.UUID, t *Target) error {
	for _, l := range t.AccessLevels {
		if _, err := tx.Exec(ctx, `INSERT INTO target_access_levels (target_id, name, description, grants, privileges, state)
			VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)
			ON CONFLICT (target_id, name) DO UPDATE SET description = EXCLUDED.description, grants = EXCLUDED.grants,
				privileges = EXCLUDED.privileges, state = EXCLUDED.state`,
			id, l.Name, null(l.Description), string(l.Grants), jsonb(l.Privileges, "[]"), l.State); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "DELETE FROM target_network_flows WHERE target_id = $1", id); err != nil {
		return err
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

// stored is a target as the database holds it.
type stored struct {
	ID       uuid.UUID
	Revision int64
	Target
}

// load reads the target matching where (on its row, with the single
// argument arg), its levels by name and its flows by name.
func load(ctx context.Context, q store.Querier, where string, arg any, lock bool) (*stored, error) {
	st := &stored{}
	t := &st.Target
	m := &t.Metadata
	t.Kind = "Target"
	sql := `SELECT id, revision, name, scope, platform, platform_type, platform_scope, zone, state, definition,
		coalesce(display_name, ''), coalesce(description, ''), labels, coalesce(documentation_url, ''), contacts, visibility, visible_to
		FROM targets WHERE ` + where
	if lock {
		sql += " FOR UPDATE"
	}
	err := q.QueryRow(ctx, sql, arg).Scan(&st.ID, &st.Revision, &m.Name, &m.Scope, &m.Platform, &m.PlatformType, &m.PlatformScope,
		&m.Zone, &m.State, &t.Definition, &t.DisplayName, &t.Description, &t.Labels, &t.DocumentationURL, &t.Contacts,
		&t.Visibility.Mode, &t.Visibility.VisibleTo)
	if err != nil {
		return nil, err
	}
	if len(t.Visibility.VisibleTo) == 0 {
		t.Visibility.VisibleTo = nil
	}
	rows, err := q.Query(ctx, `SELECT name, coalesce(description, ''), grants, privileges, state FROM target_access_levels
		WHERE target_id = $1 ORDER BY name`, st.ID)
	if err != nil {
		return nil, err
	}
	if t.AccessLevels, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (AccessLevel, error) {
		var l AccessLevel
		err := row.Scan(&l.Name, &l.Description, &l.Grants, &l.Privileges, &l.State)
		return l, err
	}); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT name, purpose, protocol, destination, ports::text, tls, coalesce(server_name, ''),
		coalesce(description, '') FROM target_network_flows WHERE target_id = $1 ORDER BY name`, st.ID)
	if err != nil {
		return nil, err
	}
	t.NetworkFlows, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (flows.Flow, error) {
		var f flows.Flow
		var ports string
		if err := row.Scan(&f.Name, &f.Purpose, &f.Protocol, &f.Destination, &ports, &f.TLS, &f.ServerName, &f.Description); err != nil {
			return f, err
		}
		f.Ports, err = flows.ParseMultirange(ports)
		return f, err
	})
	if t.NetworkFlows == nil {
		t.NetworkFlows = []flows.Flow{}
	}
	return st, err
}

// applyUpdate writes an approved update under the target's lock, with the
// checks that depend on other rows repeated (§6.2.1 steps 2 to 5).
func (s *Service) applyUpdate(ctx context.Context, tx pgx.Tx, r *changerequests.Request, t *Target) ([]audit.Entry, error) {
	cur, err := load(ctx, tx, "id = $1", *r.ResourceID, true)
	if err != nil {
		return nil, err
	}
	if cur.Revision != *r.ExpectedRevision {
		return nil, refuse(409, "revision-conflict", "the target is at revision %d", cur.Revision)
	}
	if err := sources.Transition(cur.Metadata.State, t.Metadata.State); err != nil {
		return nil, err
	}
	var added, narrowed []string
	for _, l := range t.AccessLevels {
		c := level(&cur.Target, l.Name)
		switch {
		case c == nil:
			added = append(added, l.Name)
		case !slices.Equal(c.Privileges, l.Privileges):
			if !engine.PrivilegesNarrower(c.Privileges, l.Privileges) {
				return nil, refuse(422, "widening-not-allowed", "wider: access level %s", l.Name)
			}
			narrowed = append(narrowed, l.Name)
		}
		if c != nil {
			if err := sources.Transition(c.State, l.State); err != nil {
				return nil, err
			}
		}
	}
	if err := retirable(ctx, tx, cur, t); err != nil {
		return nil, err
	}
	m := t.Metadata
	if _, err := tx.Exec(ctx, `UPDATE targets SET definition = $2::jsonb, display_name = $3, description = $4, labels = $5::jsonb,
		documentation_url = $6, contacts = $7::jsonb, visibility = $8, visible_to = $9::jsonb, state = $10,
		revision = revision + 1, updated_at = now(), updated_by = $11 WHERE id = $1`,
		cur.ID, string(t.Definition), null(t.DisplayName), null(t.Description), jsonb(t.Labels, "{}"), null(t.DocumentationURL),
		jsonb(t.Contacts, "[]"), t.Visibility.Mode, jsonb(t.Visibility.VisibleTo, "[]"), m.State, r.RequestedBy); err != nil {
		return nil, err
	}
	if err := putLevelsAndFlows(ctx, tx, cur.ID, t); err != nil {
		return nil, err
	}
	revision := cur.Revision + 1
	entry := func(action string, snapshot map[string]any) audit.Entry {
		e := audit.Entry{ResourceType: "TARGET", ResourceID: &cur.ID, ResourceName: r.ResourceName, ChangeRequestID: &r.ID,
			Action: action, Revision: &revision}
		if snapshot != nil {
			e.Snapshot, _ = json.Marshal(snapshot) // strings and lists of strings
		}
		return e
	}
	var entries []audit.Entry
	a, _ := jcs.Transform(cur.Definition)
	b, _ := jcs.Transform(t.Definition)
	definition := !bytes.Equal(a, b)
	if changed := changes(&cur.Target, t, definition); len(changed) > 0 || len(added) > 0 || len(narrowed) > 0 {
		entries = append(entries, entry("TARGET_UPDATED", map[string]any{"changed": changed, "addedLevels": added, "narrowedLevels": narrowed}))
	}
	if m.State != cur.Metadata.State {
		entries = append(entries, entry(map[string]string{"DEPRECATED": "TARGET_DEPRECATED", "ACTIVE": "TARGET_REACTIVATED", "RETIRED": "TARGET_RETIRED"}[m.State], nil))
	}
	for _, l := range t.AccessLevels {
		if c := level(&cur.Target, l.Name); c != nil && c.State != l.State {
			action := map[string]string{"DEPRECATED": "ACCESS_LEVEL_DEPRECATED", "ACTIVE": "ACCESS_LEVEL_REACTIVATED", "RETIRED": "ACCESS_LEVEL_RETIRED"}[l.State]
			entries = append(entries, entry(action, map[string]any{"accessLevel": l.Name}))
		}
	}
	var queued int64
	if len(narrowed) > 0 { // privilege removed: before anything else (§6.8)
		n, err := store.Enqueue(ctx, tx, "TARGET", cur.ID, r.ID, 0, narrowed)
		if err != nil {
			return nil, err
		}
		queued += n
	}
	if definition {
		n, err := store.Enqueue(ctx, tx, "TARGET", cur.ID, r.ID, 1, nil)
		if err != nil {
			return nil, err
		}
		queued += n
	}
	if queued > 0 {
		entries = append(entries, entry("PROPAGATION_ENQUEUED", map[string]any{"bindings": queued}))
	}
	return entries, nil
}

// changes names the fields of a target that differ, states and levels
// excepted.
func changes(old, cur *Target, definition bool) []string {
	var out []string
	if definition {
		out = append(out, "definition")
	}
	if !slices.EqualFunc(old.NetworkFlows, cur.NetworkFlows, sameFlow) {
		out = append(out, "networkFlows")
	}
	for _, f := range []struct {
		name     string
		old, cur any
	}{
		{"displayName", old.DisplayName, cur.DisplayName}, {"description", old.Description, cur.Description},
		{"labels", old.Labels, cur.Labels}, {"documentationUrl", old.DocumentationURL, cur.DocumentationURL},
		{"contacts", old.Contacts, cur.Contacts}, {"visibility", old.Visibility, cur.Visibility},
	} {
		a, _ := json.Marshal(f.old)
		b, _ := json.Marshal(f.cur)
		if !bytes.Equal(a, b) {
			out = append(out, f.name)
		}
	}
	return out
}
