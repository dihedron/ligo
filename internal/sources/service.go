package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service files the change requests of sources, and is their
// changerequests.Resource.
type Service struct {
	DB       *pgxpool.Pool // the app pool
	Rules    *Rules
	Requests *changerequests.Service
}

// request is the body of a create or an update (§7.2.3).
type request struct {
	Source
	changerequests.Common
}

func decode(body []byte) (*request, error) {
	var req request
	if err := changerequests.Decode(body, &req, &req.Common); err != nil {
		return nil, err
	}
	return &req, nil
}

// stored is a source as the database holds it.
type stored struct {
	ID       uuid.UUID
	Revision int64
	Source
}

// Create files the registration of a source (POST /v1/admin/sources).
func (s *Service) Create(ctx context.Context, c changerequests.Caller, body []byte) (*changerequests.Request, error) {
	req, err := decode(body)
	if err != nil {
		return nil, err
	}
	if req.ExpectedRevision != nil {
		return nil, invalid("expectedRevision is only for updates")
	}
	src := req.Source
	scope, err := s.Rules.validate(&src, nil)
	if err != nil {
		return nil, err
	}
	if !c.Grants.ActsFor(scope, "") {
		return nil, refuse(403, "forbidden", "%s is no operator of %s", c.ID(), scope)
	}
	if _, err := s.load(ctx, s.DB, src.Metadata.Name, false); err == nil {
		return nil, invalid("metadata.name %q is in use", src.Metadata.Name)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return s.file(ctx, c, "CREATE", nil, &src, req)
}

// Update files a change of a source (PUT /v1/admin/sources/{name}).
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
	src := req.Source
	if src.Metadata.Name == "" {
		src.Metadata.Name = name
	}
	if src.Metadata.Name != name {
		return nil, refuse(422, "immutable-field", "metadata.name cannot change")
	}
	return s.update(ctx, c, cur, &src, req)
}

// SetState files a deprecation, a reactivation or a retirement (POST
// /v1/admin/sources/{name}/deprecate, /reactivate, /retire).
func (s *Service) SetState(ctx context.Context, c changerequests.Caller, name, op string, expectedRevision int64, approvalReference string, automationContext json.RawMessage) (*changerequests.Request, error) {
	to, ok := map[string]string{"deprecate": "DEPRECATED", "reactivate": "ACTIVE", "retire": "RETIRED"}[op]
	if !ok {
		return nil, fmt.Errorf("sources: unknown operation %q", op)
	}
	cur, err := s.current(ctx, c, name)
	if err != nil {
		return nil, err
	}
	if cur.Metadata.State == to {
		return nil, refuse(409, "invalid-transition", "the source is already %s", to)
	}
	src := cur.Source
	src.Metadata.State = to
	return s.update(ctx, c, cur, &src, &request{Common: changerequests.Common{ExpectedRevision: &expectedRevision, ApprovalReference: approvalReference, AutomationContext: automationContext}})
}

func (s *Service) update(ctx context.Context, c changerequests.Caller, cur *stored, src *Source, req *request) (*changerequests.Request, error) {
	if _, err := s.Rules.validate(src, &cur.Source); err != nil {
		return nil, err
	}
	if !c.Grants.ActsFor(cur.Metadata.Scope, "") {
		return nil, refuse(403, "forbidden", "%s is no operator of %s", c.ID(), cur.Metadata.Scope)
	}
	if src.Metadata.State == "RETIRED" {
		if err := inUse(ctx, s.DB, cur.ID); err != nil {
			return nil, err
		}
	}
	if *req.ExpectedRevision != cur.Revision {
		return nil, refuse(409, "revision-conflict", "the source is at revision %d", cur.Revision)
	}
	return s.file(ctx, c, "UPDATE", cur, src, req)
}

// current reads a source the caller can see by name (404 otherwise).
func (s *Service) current(ctx context.Context, c changerequests.Caller, name string) (*stored, error) {
	cur, err := s.load(ctx, s.DB, name, false)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Grants.Sees(cur.Metadata.Scope) {
		return nil, refuse(404, "not-found", "source %q", name)
	}
	return cur, err
}

// file files the change request of a validated source change.
func (s *Service) file(ctx context.Context, c changerequests.Caller, op string, cur *stored, src *Source, req *request) (*changerequests.Request, error) {
	payload, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	r := &changerequests.Request{ResourceType: "SOURCE", ResourceName: src.Metadata.Name, Operation: op,
		Consent: changerequests.ConsentAll, OwnerScope: src.Metadata.Scope, ExpectedRevision: req.ExpectedRevision,
		Payload: payload, AutomationContext: req.AutomationContext}
	if cur != nil {
		r.ResourceID = &cur.ID
	}
	err = s.Requests.Create(ctx, c, r, []changerequests.Candidate{{Side: "OWNER", Scope: src.Metadata.Scope}}, req.ApprovalReference)
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.ConstraintName == "uq_cr_one_pending_per_resource" {
		return nil, refuse(409, "change-request-pending", "source %q has a pending change request", src.Metadata.Name)
	}
	return r, err
}

// Revalidate re-runs the pipeline on the stored request (approval step 2)
// and returns its normalized payload.
func (s *Service) Revalidate(ctx context.Context, r *changerequests.Request) (json.RawMessage, error) {
	var src Source
	if err := json.Unmarshal(r.Payload, &src); err != nil {
		return nil, err
	}
	var cur *Source
	if r.Operation == "CREATE" {
		src.Metadata.Scope, src.Metadata.State = "", "" // derived again
	} else {
		st, err := s.loadID(ctx, s.DB, *r.ResourceID, false)
		if err != nil {
			return nil, err
		}
		cur = &st.Source
	}
	if _, err := s.Rules.validate(&src, cur); err != nil {
		return nil, err
	}
	return json.Marshal(src)
}

// Apply writes an approved change (§6.2.1 steps 2 to 5).
func (s *Service) Apply(ctx context.Context, tx pgx.Tx, r *changerequests.Request) ([]audit.Entry, error) {
	var src Source
	if err := json.Unmarshal(r.Payload, &src); err != nil {
		return nil, err
	}
	if r.Operation == "CREATE" {
		id := uuid.NewV7()
		if err := insert(ctx, tx, id, &src, r.RequestedBy); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, "UPDATE change_requests SET resource_id = $2 WHERE id = $1", r.ID, id); err != nil {
			return nil, err
		}
		r.ResourceID = &id
		return []audit.Entry{entry(r, "SOURCE_REGISTERED", 1, nil)}, nil
	}
	cur, err := s.loadID(ctx, tx, *r.ResourceID, true)
	if err != nil {
		return nil, err
	}
	if cur.Revision != *r.ExpectedRevision {
		return nil, refuse(409, "revision-conflict", "the source is at revision %d", cur.Revision)
	}
	if err := transition(cur.Metadata.State, src.Metadata.State); err != nil {
		return nil, err
	}
	if err := s.Rules.narrows(cur.Identity.SVIDRegex, src.Identity.SVIDRegex); err != nil {
		return nil, err
	}
	if src.Metadata.State == "RETIRED" {
		if err := inUse(ctx, tx, cur.ID); err != nil {
			return nil, err
		}
	}
	if err := update(ctx, tx, cur.ID, &src, r.RequestedBy); err != nil {
		return nil, err
	}
	revision := cur.Revision + 1
	var entries []audit.Entry
	if changed := changes(&cur.Source, &src); len(changed) > 0 {
		snap := map[string]any{"changed": changed}
		if src.Identity.SVIDRegex != cur.Identity.SVIDRegex {
			snap["oldSvidRegex"], snap["newSvidRegex"] = cur.Identity.SVIDRegex, src.Identity.SVIDRegex
		}
		entries = append(entries, entry(r, "SOURCE_UPDATED", revision, snap))
	}
	if src.Metadata.State != cur.Metadata.State {
		action := map[string]string{"DEPRECATED": "SOURCE_DEPRECATED", "ACTIVE": "SOURCE_REACTIVATED", "RETIRED": "SOURCE_RETIRED"}[src.Metadata.State]
		entries = append(entries, entry(r, action, revision, nil))
	}
	if src.Identity.SVIDRegex != cur.Identity.SVIDRegex {
		// a regex can only narrow (§3.7): priority 0
		tag, err := tx.Exec(ctx, `INSERT INTO binding_propagation_queue (binding_id, cause_change_request_id, cause, priority)
			SELECT id, $2, 'SOURCE', 0 FROM bindings WHERE source_id = $1 AND phase NOT IN ('DELETING', 'DELETE_FAILED')
			ON CONFLICT (binding_id) DO UPDATE SET cause_change_request_id = EXCLUDED.cause_change_request_id,
				cause = EXCLUDED.cause, priority = least(binding_propagation_queue.priority, EXCLUDED.priority),
				enqueued_at = now(), attempts = 0`, cur.ID, r.ID)
		if err != nil {
			return nil, fmt.Errorf("sources: enqueue propagation: %w", err)
		}
		if n := tag.RowsAffected(); n > 0 {
			entries = append(entries, entry(r, "PROPAGATION_ENQUEUED", revision, map[string]any{"bindings": n, "priority": 0}))
		}
	}
	return entries, nil
}

// changes names the fields of a source that differ, state excepted.
func changes(old, cur *Source) []string {
	var out []string
	for _, f := range []struct {
		name     string
		old, cur any
	}{
		{"identity", old.Identity, cur.Identity}, {"displayName", old.DisplayName, cur.DisplayName},
		{"description", old.Description, cur.Description}, {"labels", old.Labels, cur.Labels},
		{"externalRefs", old.ExternalRefs, cur.ExternalRefs}, {"contacts", old.Contacts, cur.Contacts},
		{"visibility", old.Visibility, cur.Visibility},
	} {
		a, _ := json.Marshal(f.old)
		b, _ := json.Marshal(f.cur)
		if !bytes.Equal(a, b) {
			out = append(out, f.name)
		}
	}
	return out
}

func entry(r *changerequests.Request, action string, revision int64, snapshot map[string]any) audit.Entry {
	e := audit.Entry{ResourceType: "SOURCE", ResourceID: r.ResourceID, ResourceName: r.ResourceName,
		ChangeRequestID: &r.ID, Action: action, Revision: &revision}
	if snapshot != nil {
		e.Snapshot, _ = json.Marshal(snapshot) // strings and numbers
	}
	return e
}

// inUse refuses to retire a source that still has bindings.
func inUse(ctx context.Context, q store.Querier, id uuid.UUID) error {
	var n int
	if err := q.QueryRow(ctx, "SELECT count(*) FROM bindings WHERE source_id = $1", id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return refuse(409, "resource-in-use", "the source has %d bindings", n)
	}
	return nil
}

const columns = `id, revision, name, scope, state, trust_domain, svid_regex, sample_spiffe_ids, coalesce(display_name, ''),
	coalesce(description, ''), labels, external_refs, contacts, visibility, visible_to`

func scan(row pgx.Row) (*stored, error) {
	var st stored
	st.Kind = "Source"
	err := row.Scan(&st.ID, &st.Revision, &st.Metadata.Name, &st.Metadata.Scope, &st.Metadata.State, &st.Identity.TrustDomain,
		&st.Identity.SVIDRegex, &st.Identity.SampleSPIFFEIDs, &st.DisplayName, &st.Description, &st.Labels, &st.ExternalRefs,
		&st.Contacts, &st.Visibility.Mode, &st.Visibility.VisibleTo)
	if len(st.Visibility.VisibleTo) == 0 {
		st.Visibility.VisibleTo = nil
	}
	return &st, err
}

// load reads the non-retired source called name.
func (s *Service) load(ctx context.Context, q store.Querier, name string, lock bool) (*stored, error) {
	return scan(q.QueryRow(ctx, "SELECT "+columns+" FROM sources WHERE name = $1 AND state <> 'RETIRED'"+forUpdate(lock), name))
}

func (s *Service) loadID(ctx context.Context, q store.Querier, id uuid.UUID, lock bool) (*stored, error) {
	return scan(q.QueryRow(ctx, "SELECT "+columns+" FROM sources WHERE id = $1"+forUpdate(lock), id))
}

func forUpdate(lock bool) string {
	if lock {
		return " FOR UPDATE"
	}
	return ""
}

// jsonb is v as JSON, or empty (an empty object or array) when v is nil.
func jsonb(v any, empty string) string {
	data, err := json.Marshal(v)
	if err != nil || string(data) == "null" {
		return empty
	}
	return string(data)
}

func insert(ctx context.Context, tx pgx.Tx, id uuid.UUID, s *Source, actor string) error {
	_, err := tx.Exec(ctx, `INSERT INTO sources (id, name, scope, trust_domain, svid_regex, sample_spiffe_ids, display_name,
		description, labels, external_refs, contacts, visibility, visible_to, state, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9::jsonb, $10::jsonb, $11::jsonb, $12, $13::jsonb, 'ACTIVE', $14, $14)`,
		id, s.Metadata.Name, s.Metadata.Scope, s.Identity.TrustDomain, s.Identity.SVIDRegex, jsonb(s.Identity.SampleSPIFFEIDs, "[]"),
		null(s.DisplayName), null(s.Description), jsonb(s.Labels, "{}"), jsonb(s.ExternalRefs, "{}"), jsonb(s.Contacts, "[]"),
		s.Visibility.Mode, jsonb(s.Visibility.VisibleTo, "[]"), actor)
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.ConstraintName == "uq_sources_name" {
		return invalid("metadata.name %q is in use", s.Metadata.Name)
	}
	return err
}

func update(ctx context.Context, tx pgx.Tx, id uuid.UUID, s *Source, actor string) error {
	_, err := tx.Exec(ctx, `UPDATE sources SET svid_regex = $2, sample_spiffe_ids = $3::jsonb, display_name = $4, description = $5,
		labels = $6::jsonb, external_refs = $7::jsonb, contacts = $8::jsonb, visibility = $9, visible_to = $10::jsonb, state = $11,
		revision = revision + 1, updated_at = now(), updated_by = $12
		WHERE id = $1`,
		id, s.Identity.SVIDRegex, jsonb(s.Identity.SampleSPIFFEIDs, "[]"), null(s.DisplayName), null(s.Description),
		jsonb(s.Labels, "{}"), jsonb(s.ExternalRefs, "{}"), jsonb(s.Contacts, "[]"), s.Visibility.Mode,
		jsonb(s.Visibility.VisibleTo, "[]"), s.Metadata.State, actor)
	return err
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}
