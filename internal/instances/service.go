package instances

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"uuid"

	"github.com/dihedron/ligo/internal/accounts"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Plugins is what the service asks of the plugin manager (§6 rules 6 to 8).
type Plugins interface {
	// Validate runs the plugin's ValidateInstance: the SPIFFE ID the
	// instance would resolve and the endpoints it would use.
	Validate(ctx context.Context, k Kind, d *Definition) (spiffeID string, endpoints []string, err error)
	// Resolved are the SPIFFE IDs of the running instances of a type in a
	// realm, by instance name.
	Resolved(typ, realm string) map[string]string
	// Wire checks a platform's wiring against what its plugins describe,
	// and fills an omitted secretStorageStrategy (§5.6).
	Wire(ctx context.Context, d *Definition) error
}

// Service files the change requests of instances, and is their
// changerequests.Resource, for the three kinds.
type Service struct {
	DB        *pgxpool.Pool // the app pool
	Env       *Env
	Instances Source
	Signer    sealing.Signer
	Plugins   Plugins
	Requests  *changerequests.Service
	Logger    *slog.Logger
	// Tightened runs once a platform UPDATE has committed: the check of
	// access levels and flows against the platform's new bounds (§5 rule 7).
	Tightened func(ctx context.Context)
}

// Applied runs Tightened after a platform UPDATE.
func (s *Service) Applied(ctx context.Context, r *changerequests.Request) {
	if Kind(r.ResourceType) == Platform && r.Operation == "UPDATE" && s.Tightened != nil {
		s.Tightened(context.WithoutCancel(ctx))
	}
}

// request is the body of a create or an update.
type request struct {
	Definition
	changerequests.Common
}

func refuse(status int, slug, format string, args ...any) *changerequests.Error {
	return &changerequests.Error{Status: status, Slug: slug, Detail: fmt.Sprintf(format, args...)}
}

func invalid(err error) *changerequests.Error {
	return refuse(422, "validation-failed", "%v", err)
}

// stored is an instance as the database holds it.
type stored struct {
	ID       uuid.UUID
	Revision int64
	Status   string
	Definition
}

// Create files the creation of an instance of kind k.
func (s *Service) Create(ctx context.Context, c changerequests.Caller, k Kind, body []byte) (*changerequests.Request, error) {
	var req request
	if err := changerequests.Decode(body, &req, &req.Common); err != nil {
		return nil, err
	}
	if req.ExpectedRevision != nil {
		return nil, refuse(422, "validation-failed", "expectedRevision is only for updates")
	}
	d := &req.Definition
	if err := s.authorize(c, k, d); err != nil {
		return nil, err
	}
	if _, err := s.load(ctx, s.DB, k, d.Metadata.Name, false); err == nil {
		return nil, refuse(409, "invalid-transition", "%s %q exists, or existed: a retired name is not reused", k, d.Metadata.Name)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err := s.validate(ctx, k, d, nil); err != nil {
		return nil, err
	}
	return s.file(ctx, c, k, "CREATE", nil, d, &req.Common)
}

// Update files a change of an instance of kind k.
func (s *Service) Update(ctx context.Context, c changerequests.Caller, k Kind, name string, body []byte) (*changerequests.Request, error) {
	var req request
	if err := changerequests.Decode(body, &req, &req.Common); err != nil {
		return nil, err
	}
	if req.ExpectedRevision == nil {
		return nil, refuse(422, "validation-failed", "expectedRevision is required")
	}
	d := &req.Definition
	if d.Metadata.Name == "" {
		d.Metadata.Name = name
	}
	if d.Metadata.Name != name {
		return nil, refuse(422, "immutable-field", "metadata.name cannot change")
	}
	cur, err := s.current(ctx, c, k, name)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(c, k, d); err != nil {
		return nil, err
	}
	if *req.ExpectedRevision != cur.Revision {
		return nil, refuse(409, "revision-conflict", "the instance is at revision %d", cur.Revision)
	}
	if err := s.validate(ctx, k, d, &cur.Definition); err != nil {
		return nil, err
	}
	return s.file(ctx, c, k, "UPDATE", cur, d, &req.Common)
}

// Retire files the retirement of an instance (DELETE, §4.3).
func (s *Service) Retire(ctx context.Context, c changerequests.Caller, k Kind, name string, common changerequests.Common) (*changerequests.Request, error) {
	if common.ExpectedRevision == nil {
		return nil, refuse(422, "validation-failed", "expectedRevision is required")
	}
	cur, err := s.current(ctx, c, k, name)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(c, k, &cur.Definition); err != nil {
		return nil, err
	}
	if *common.ExpectedRevision != cur.Revision {
		return nil, refuse(409, "revision-conflict", "the instance is at revision %d", cur.Revision)
	}
	if err := s.inUse(ctx, s.DB, k, name); err != nil {
		return nil, err
	}
	return s.file(ctx, c, k, "DELETE", cur, &cur.Definition, &common)
}

// Get reads an ACTIVE instance the caller sees, with its revision; its
// definition is for the people who file and decide its requests (§10.1).
func (s *Service) Get(ctx context.Context, c changerequests.Caller, k Kind, name string) (revision int64, d *Definition, decider bool, err error) {
	cur, err := s.current(ctx, c, k, name)
	if err != nil {
		return 0, nil, false, err
	}
	j := cur.Metadata.Jurisdiction
	return cur.Revision, &cur.Definition, c.Grants.Operator(j) || c.Grants.CanApprove(j), nil
}

// authorize: the caller acts for the instance's jurisdiction, as an
// operator (§5 rule 3); a grant scoped to platforms gives nothing here.
func (s *Service) authorize(c changerequests.Caller, k Kind, d *Definition) error {
	if got, err := d.KindOf(); err != nil || got != k {
		return refuse(422, "validation-failed", "kind must be %s", k.ManifestKind())
	}
	if !c.Grants.ActsFor(d.Metadata.Jurisdiction, "") {
		return refuse(403, "forbidden", "%s is no operator of %s", c.ID(), d.Metadata.Jurisdiction)
	}
	return nil
}

// current reads an ACTIVE instance the caller can see (404 otherwise).
func (s *Service) current(ctx context.Context, c changerequests.Caller, k Kind, name string) (*stored, error) {
	cur, err := s.load(ctx, s.DB, k, name, false)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (cur.Status != "ACTIVE" || !c.Grants.Sees(cur.Metadata.Jurisdiction)) {
		return nil, refuse(404, "not-found", "%s %q", k.ManifestKind(), name)
	}
	return cur, err
}

// validate runs §6 on d, normalizing it; cur is the instance it changes.
func (s *Service) validate(ctx context.Context, k Kind, d *Definition, cur *Definition) error {
	d.Normalize()
	if err := s.Env.Check(d); err != nil {
		return invalid(err)
	}
	if cur != nil {
		if err := Immutable(cur, d); err != nil {
			return err
		}
		if k == Platform {
			if err := s.keepsTargets(ctx, cur, d); err != nil {
				return err
			}
		}
	} else if _, err := accounts.Require(ctx, s.DB, s.Env.Accounts, d.Metadata.Jurisdiction); err != nil {
		return err
	}
	if k == Platform {
		if err := s.wiring(ctx, d); err != nil {
			return err
		}
	}
	id, endpoints, err := s.Plugins.Validate(ctx, k, d)
	if err != nil {
		return err
	}
	if err := s.Env.Bounded(d, endpoints); err != nil {
		return invalid(err)
	}
	return s.shared(k, d, id)
}

// keepsTargets refuses a platform change that would strand an existing
// target: its targetJurisdictions must still cover each one, and its
// namespaceTemplate cannot change while it has targets (§4.3).
func (s *Service) keepsTargets(ctx context.Context, cur, d *Definition) error {
	rows, err := s.DB.Query(ctx, "SELECT name, jurisdiction FROM targets WHERE platform = $1 AND state <> 'RETIRED' ORDER BY name", d.Metadata.Name)
	if err != nil {
		return err
	}
	held, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([2]string, error) {
		var v [2]string
		return v, r.Scan(&v[0], &v[1])
	})
	if err != nil {
		return err
	}
	if len(held) > 0 && d.NamespaceTemplate != cur.NamespaceTemplate {
		return refuse(422, "validation-failed", "namespaceTemplate cannot change while the platform has %d targets", len(held))
	}
	for _, t := range held {
		if !slices.ContainsFunc(d.TargetJurisdictions, func(p string) bool { return charter.JurisdictionMatches(p, t[1]) }) {
			return refuse(422, "validation-failed", "targetJurisdictions would leave target %s (%s) outside them", t[0], t[1])
		}
	}
	return nil
}

// wiring checks rule 6: the instances a platform names are ACTIVE, in its
// realm, and fit it.
func (s *Service) wiring(ctx context.Context, d *Definition) error {
	set := s.Instances.Current()
	for role, w := range map[Kind]*Wiring{IdentityProvider: d.IdentityProvider, SecretStore: d.SecretStore} {
		in, ok := set.Get(role, w.Instance)
		switch {
		case !ok || in.Type != w.Type:
			return refuse(422, "validation-failed", "%s %s/%s is not an ACTIVE instance", role.ManifestKind(), w.Type, w.Instance)
		case in.Metadata.Realm != d.Metadata.Realm:
			return refuse(422, "validation-failed", "%s %q is in realm %s, the platform in %s", role.ManifestKind(), w.Instance, in.Metadata.Realm, d.Metadata.Realm)
		}
	}
	if err := s.Plugins.Wire(ctx, d); err != nil {
		var e *changerequests.Error
		if errors.As(err, &e) {
			return e
		}
		return refuse(422, "validation-failed", "%v", err)
	}
	return nil
}

// shared checks rule 7: the SVID id resolves to no other instance of the
// same plugin process, unless both allow it and share a jurisdiction.
func (s *Service) shared(k Kind, d *Definition, id string) error {
	if id == "" { // a builtin has no SVID
		return nil
	}
	set := s.Instances.Current()
	for name, other := range s.Plugins.Resolved(d.Type, d.Metadata.Realm) {
		if name == d.Metadata.Name || other != id {
			continue
		}
		o, ok := set.Get(k, name)
		allowed := ok && o.Metadata.Jurisdiction == d.Metadata.Jurisdiction &&
			o.SVIDSelector != nil && o.SVIDSelector.AllowSharedSVID && d.SVIDSelector != nil && d.SVIDSelector.AllowSharedSVID
		if !allowed {
			return refuse(422, "validation-failed", "svidSelector resolves %s, the SVID of %s %q: sharing needs allowSharedSvid on both and one jurisdiction",
				id, k.ManifestKind(), name)
		}
	}
	return nil
}

// compose builds the change request of a validated change.
func compose(k Kind, op string, cur *stored, d *Definition, common *changerequests.Common) (*changerequests.Request, error) {
	payload := json.RawMessage(`{}`)
	if op != "DELETE" {
		var err error
		if payload, _, err = d.Normalized(); err != nil {
			return nil, err
		}
	}
	r := &changerequests.Request{ResourceType: string(k), ResourceName: d.Metadata.Name, Operation: op,
		Consent: changerequests.ConsentAll, OwnerJurisdiction: d.Metadata.Jurisdiction, Realm: d.Metadata.Realm,
		ExpectedRevision: common.ExpectedRevision, Payload: payload, AutomationContext: common.AutomationContext}
	if cur != nil {
		r.ResourceID = &cur.ID
	}
	return r, nil
}

// file files the change request: one OWNER side, always a person (§5).
func (s *Service) file(ctx context.Context, c changerequests.Caller, k Kind, op string, cur *stored, d *Definition, common *changerequests.Common) (*changerequests.Request, error) {
	r, err := compose(k, op, cur, d, common)
	if err != nil {
		return nil, err
	}
	err = s.Requests.Create(ctx, c, r, []changerequests.Candidate{{Side: "OWNER", Jurisdiction: d.Metadata.Jurisdiction, AlwaysHuman: true}}, common.ApprovalReference)
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.ConstraintName == "uq_cr_one_pending_per_resource" {
		return nil, refuse(409, "change-request-pending", "%s %q has a pending change request", k.ManifestKind(), d.Metadata.Name)
	}
	return r, err
}

// Revalidate re-runs §6 on the stored request (approval step 2) and returns
// its normalized payload (§5 rule 5).
func (s *Service) Revalidate(ctx context.Context, r *changerequests.Request) (json.RawMessage, error) {
	k := Kind(r.ResourceType)
	if r.Operation == "DELETE" {
		cur, err := s.loadID(ctx, s.DB, *r.ResourceID, false)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(`{}`), s.inUse(ctx, s.DB, k, cur.Metadata.Name)
	}
	d, err := Decode(r.Payload)
	if err != nil {
		return nil, err
	}
	var cur *Definition
	if r.Operation == "UPDATE" {
		st, err := s.loadID(ctx, s.DB, *r.ResourceID, false)
		if err != nil {
			return nil, err
		}
		cur = &st.Definition
	}
	if err := s.validate(ctx, k, d, cur); err != nil {
		return nil, err
	}
	payload, _, err := d.Normalized()
	return payload, err
}

// Diff is how an UPDATE changes the instance (§7.2.3).
func (s *Service) Diff(ctx context.Context, r *changerequests.Request) (any, error) {
	cur, err := s.loadID(ctx, s.DB, *r.ResourceID, false)
	if err != nil {
		return nil, err
	}
	old, _, err := cur.Normalized()
	if err != nil {
		return nil, err
	}
	return changerequests.Diff(old, r.Payload)
}

// Apply writes an approved change, signed with the audit key (§8).
func (s *Service) Apply(ctx context.Context, tx pgx.Tx, r *changerequests.Request) ([]audit.Entry, error) {
	k := Kind(r.ResourceType)
	action := map[string]string{"CREATE": "_CREATED", "UPDATE": "_UPDATED", "DELETE": "_RETIRED"}[r.Operation]
	if r.Operation == "CREATE" {
		d, err := Decode(r.Payload)
		if err != nil {
			return nil, err
		}
		_, sha, err := d.Normalized()
		if err != nil {
			return nil, err
		}
		keyID, sig, err := s.Signer.Sign(ctx, Signed(k, d.Metadata.Name, 1, sha))
		if err != nil {
			return nil, err
		}
		id := uuid.NewV7()
		_, err = tx.Exec(ctx, `INSERT INTO instances (id, kind, name, type, realm, jurisdiction, definition, definition_sha256, key_id, signature, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)`,
			id, k, d.Metadata.Name, d.Type, d.Metadata.Realm, d.Metadata.Jurisdiction, r.Payload, sha, keyID, sig, r.RequestedBy)
		if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.ConstraintName == "uq_instances_kind_name" {
			return nil, refuse(409, "invalid-transition", "%s %q exists, or existed", k.ManifestKind(), d.Metadata.Name)
		}
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, "UPDATE change_requests SET resource_id = $2 WHERE id = $1", r.ID, id); err != nil {
			return nil, err
		}
		r.ResourceID = &id
		return []audit.Entry{entry(r, string(k)+action, 1, map[string]any{"definitionSha256": sha})}, nil
	}
	cur, err := s.loadID(ctx, tx, *r.ResourceID, true)
	if err != nil {
		return nil, err
	}
	if cur.Status != "ACTIVE" || cur.Revision != *r.ExpectedRevision {
		return nil, refuse(409, "revision-conflict", "the instance is at revision %d, %s", cur.Revision, cur.Status)
	}
	revision := cur.Revision + 1
	if r.Operation == "DELETE" {
		if err := s.inUse(ctx, tx, k, cur.Metadata.Name); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE instances SET status = 'RETIRED', revision = $2, updated_at = now(), updated_by = $3 WHERE id = $1`,
			cur.ID, revision, r.RequestedBy); err != nil {
			return nil, err
		}
		return []audit.Entry{entry(r, string(k)+action, revision, nil)}, nil
	}
	d, err := Decode(r.Payload)
	if err != nil {
		return nil, err
	}
	_, sha, err := d.Normalized()
	if err != nil {
		return nil, err
	}
	keyID, sig, err := s.Signer.Sign(ctx, Signed(k, d.Metadata.Name, revision, sha))
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE instances SET definition = $2, definition_sha256 = $3, key_id = $4, signature = $5, revision = $6,
		updated_at = now(), updated_by = $7 WHERE id = $1`, cur.ID, r.Payload, sha, keyID, sig, revision, r.RequestedBy); err != nil {
		return nil, err
	}
	old, _, err := cur.Normalized()
	if err != nil {
		return nil, err
	}
	changes, err := changerequests.Diff(old, r.Payload)
	if err != nil {
		return nil, err
	}
	fields := make([]string, 0, len(changes))
	for _, c := range changes {
		fields = append(fields, c.Field)
	}
	return []audit.Entry{entry(r, string(k)+action, revision, map[string]any{"definitionSha256": sha, "changed": fields})}, nil
}

func entry(r *changerequests.Request, action string, revision int64, snapshot map[string]any) audit.Entry {
	e := audit.Entry{ResourceType: r.ResourceType, ResourceID: r.ResourceID, ResourceName: r.ResourceName,
		ChangeRequestID: &r.ID, Action: action, Revision: &revision}
	if snapshot != nil {
		e.Snapshot, _ = json.Marshal(snapshot) // strings
	}
	return e
}

// inUse refuses to retire an instance still referenced (§6 rule 9).
func (s *Service) inUse(ctx context.Context, q store.Querier, k Kind, name string) error {
	var n int
	var err error
	switch k {
	case Platform:
		err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM targets WHERE platform = $1 AND state <> 'RETIRED')
			+ (SELECT count(*) FROM bindings WHERE platform = $1)`, name).Scan(&n)
	case IdentityProvider:
		err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM bindings WHERE identity_provider_instance = $1)
			+ (SELECT count(*) FROM binding_stage_state WHERE stage = 'IDENTITY' AND provider_instance = $1)`, name).Scan(&n)
	case SecretStore:
		err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM bindings WHERE secret_store_instance = $1)
			+ (SELECT count(*) FROM binding_stage_state WHERE stage = 'SECRET_STORE' AND provider_instance = $1)`, name).Scan(&n)
	}
	if err != nil {
		return err
	}
	if n > 0 {
		return refuse(409, "instance-in-use", "%s %q has %d targets or bindings", k.ManifestKind(), name, n)
	}
	if k == Platform {
		return nil
	}
	for _, p := range s.Instances.Current().List(Platform) {
		if w := map[Kind]*Wiring{IdentityProvider: p.IdentityProvider, SecretStore: p.SecretStore}[k]; w != nil && w.Instance == name {
			return refuse(409, "instance-in-use", "platform %q is wired to %s %q", p.Metadata.Name, k.ManifestKind(), name)
		}
	}
	return nil
}

const columns = "id, revision, status, definition"

func scan(row pgx.Row) (*stored, error) {
	var st stored
	var def []byte
	if err := row.Scan(&st.ID, &st.Revision, &st.Status, &def); err != nil {
		return nil, err
	}
	d, err := Decode(def)
	if err != nil {
		return nil, err
	}
	st.Definition = *d
	return &st, nil
}

// load reads the instance of kind k called name, of any status.
func (s *Service) load(ctx context.Context, q store.Querier, k Kind, name string, lock bool) (*stored, error) {
	return scan(q.QueryRow(ctx, "SELECT "+columns+" FROM instances WHERE kind = $1 AND name = $2"+forUpdate(lock), k, name))
}

func (s *Service) loadID(ctx context.Context, q store.Querier, id uuid.UUID, lock bool) (*stored, error) {
	return scan(q.QueryRow(ctx, "SELECT "+columns+" FROM instances WHERE id = $1"+forUpdate(lock), id))
}

func forUpdate(lock bool) string {
	if lock {
		return " FOR UPDATE"
	}
	return ""
}
