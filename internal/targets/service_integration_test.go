//go:build integration

package targets

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// insecure: CI's container has no TLS; the lab's DSNs use verify-full.
var insecure = os.Getenv("CI") != ""

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

func caller(name, role string, scopes ...string) changerequests.Caller {
	return changerequests.Caller{Principal: authz.Principal{Name: name}, Grants: authz.Grants{{Role: role, Scopes: scopes}}}
}

var (
	alice = caller("alice", config.RoleOperator, "dc/corp-prod/ledger") // ledger operator
	bob   = caller("bob", config.RoleApprover, "dc/corp-prod/ledger")   // ledger approver
	dora  = caller("dora", config.RoleApprover, "dc/corp-prod")         // platform approver
	marco = caller("marco", config.RoleApprover, "dc/corp-prod/*")      // approves both
	eve   = caller("eve", config.RoleOperator, "cloud/*")
)

func setup(t *testing.T) (*Service, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), insecure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	cfg := example(t)
	s := &Service{DB: pools.App, Rules: rules(t), Validate: (&plugin{}).validate}
	s.Requests = &changerequests.Service{DB: pools.App, Policy: cfg.Policy(), TTL: cfg.Authorization.Approval.ChangeRequestTTL,
		Resources: map[string]changerequests.Resource{"TARGET": s}}
	return s, owner
}

func body(t *testing.T, tg Target) []byte {
	t.Helper()
	data, err := json.Marshal(tg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// unique gives tg a name of its own, removed with its rows at the end of
// the test.
func unique(t *testing.T, owner *pgxpool.Pool, tg *Target) {
	tg.Metadata.Name += "-" + uuid.NewV7().String()[24:]
	name := tg.Metadata.Name
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from change_requests where resource_type = 'TARGET' and resource_name = $1", name)
		_, _ = owner.Exec(ctx, "delete from target_network_flows where target_id in (select id from targets where name = $1)", name)
		_, _ = owner.Exec(ctx, "delete from target_access_levels where target_id in (select id from targets where name = $1)", name)
		_, _ = owner.Exec(ctx, "delete from targets where name = $1", name)
	})
}

// TestAC63: a target needs its owner's and its platform's consent, from two
// different people; a missing resource and a scope outside target_scopes
// are refused.
func TestAC63(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	tg := ledger()
	unique(t, owner, &tg)
	if _, err := s.Create(ctx, eve, body(t, tg)); slug(err) != "forbidden" {
		t.Errorf("operator of another scope: %v", err)
	}
	r, err := s.Create(ctx, alice, body(t, tg))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || len(r.Sides) != 2 || r.Sides[0].Name != "OWNER" || r.Sides[1].Name != "PLATFORM" ||
		r.Sides[0].Scope != "dc/corp-prod/ledger" || r.Sides[1].Scope != "dc/corp-prod" || r.Zone != "prod" || r.PlatformScope != "dc/corp-prod" {
		t.Fatalf("request %+v", r)
	}
	if _, err := s.Requests.Approve(ctx, marco, r.ID, r.PayloadSHA256, "OWNER", "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Requests.Approve(ctx, marco, r.ID, r.PayloadSHA256, "PLATFORM", "ok"); slug(err) != "distinct-approver-required" {
		t.Errorf("one person, both sides: %v", err)
	}
	if _, err := s.Requests.Approve(ctx, dora, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	var state string
	var levels, flows int
	err = owner.QueryRow(ctx, `select t.state, (select count(*) from target_access_levels where target_id = t.id),
		(select count(*) from target_network_flows where target_id = t.id) from targets t where name = $1`, tg.Metadata.Name).Scan(&state, &levels, &flows)
	if err != nil || state != "ACTIVE" || levels != 2 || flows != 1 {
		t.Errorf("target %s, %d levels, %d flows (%v)", state, levels, flows, err)
	}
	var privileges string
	if err := owner.QueryRow(ctx, `select privileges::text from target_access_levels l join targets t on t.id = l.target_id
		where t.name = $1 and l.name = 'write'`, tg.Metadata.Name).Scan(&privileges); err != nil || privileges != `["role:LEDGER_RO_ROLE", "role:LEDGER_RW_ROLE"]` {
		t.Errorf("privileges %s (%v)", privileges, err)
	}

	missing := ledger()
	missing.Definition = json.RawMessage(`{"schema":"LEDGER_MISSING"}`)
	unique(t, owner, &missing)
	if _, err := s.Create(ctx, alice, body(t, missing)); slug(err) != "validation-failed" {
		t.Errorf("missing resource: %v", err)
	}
	outside := ledger()
	outside.Metadata.Scope = "cloud/fin-01/payments"
	unique(t, owner, &outside)
	if _, err := s.Create(ctx, alice, body(t, outside)); slug(err) != "validation-failed" {
		t.Errorf("scope outside target_scopes: %v", err)
	}
}

// TestAC64Ports: the database refuses a flow with port 0 (chk_flow_ports).
func TestAC64Ports(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	tg := ledger()
	unique(t, owner, &tg)
	r, err := s.Create(ctx, alice, body(t, tg))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Requests.Approve(ctx, dora, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	_, err = owner.Exec(ctx, `insert into target_network_flows (target_id, name, protocol, destination, ports, tls)
		select id, 'zero', 'TCP', 'ledger-db.prod.internal', '{[0,1)}', false from targets where name = $1`, tg.Metadata.Name)
	if err == nil {
		t.Error("a flow with port 0 was inserted")
	}
}

// approved files tg and has bob and dora approve it.
func approved(t *testing.T, s *Service, r *changerequests.Request, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []changerequests.Caller{bob, dora} {
		if r.Status != "PENDING" {
			break
		}
		got, err := s.Requests.Approve(context.Background(), c, r.ID, r.PayloadSHA256, "", "ok")
		if err != nil {
			t.Fatalf("%s approves: %v", c.ID(), err)
		}
		r = got
	}
	if r.Status != "APPLIED" {
		t.Fatalf("request %s", r.Status)
	}
}

// bindingAt commits a source and its binding to target at level, removed at
// the end of the test.
func bindingAt(t *testing.T, o *pgxpool.Pool, target uuid.UUID, level string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	source, binding := uuid.NewV7(), uuid.NewV7()
	suffix := binding.String()[24:]
	regex := `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/` + suffix + `$`
	err := pgx.BeginFunc(ctx, o, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by)
			values ($1, $2, 'cloud/fin-01/payments', 'cloud.internal', $3, 't', 't')`, source, "s-"+suffix, regex); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `insert into bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
			identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
			source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision,
			source_trust_domain, source_svid_regex, requested_spec, created_by, updated_by)
			values ($1, $2, $3, $4, $5, 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', 'vault-prod', 'vault-static', 'bnd_' || left(md5($1::uuid::text), 16),
			'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod', $6, 1, 1, 'cloud.internal', $7, '{}', 't', 't')`,
			binding, "b-"+suffix, source, target, level, "ligo:apply:"+binding.String()+":r1:a1", regex)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = o.Exec(ctx, "delete from bindings where id = $1", binding)
		_, _ = o.Exec(ctx, "delete from sources where id = $1", source)
	})
	return binding
}

// queued is the priority a binding is queued at by request cr, or -1.
func queued(t *testing.T, o *pgxpool.Pool, binding uuid.UUID) int {
	t.Helper()
	p := -1
	err := o.QueryRow(context.Background(), "select priority from binding_propagation_queue where binding_id = $1", binding).Scan(&p)
	if err != nil && err != pgx.ErrNoRows {
		t.Fatal(err)
	}
	return p
}

// TestAC65: narrowing a level needs the owner and the platform and re-applies
// only that level's bindings, at priority 0; a widening is refused; a new
// level re-applies nothing. A level in use cannot be retired; deprecating
// one needs only the owner. A new definition re-applies every binding at
// priority 1 (§6.2.1).
func TestAC65(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	tg := ledger()
	unique(t, owner, &tg)
	r, err := s.Create(ctx, alice, body(t, tg))
	approved(t, s, r, err)
	var id uuid.UUID
	if err := owner.QueryRow(ctx, "select id from targets where name = $1", tg.Metadata.Name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	read, write := bindingAt(t, owner, id, "read"), bindingAt(t, owner, id, "write")
	revision := int64(1)
	update := func(edit func(*Target)) (*changerequests.Request, error) {
		u := tg
		u.AccessLevels = append([]AccessLevel{}, tg.AccessLevels...)
		edit(&u)
		data, _ := json.Marshal(map[string]any{"metadata": u.Metadata, "definition": u.Definition, "accessLevels": u.AccessLevels,
			"networkFlows": u.NetworkFlows, "expectedRevision": revision})
		return s.Update(ctx, alice, tg.Metadata.Name, data)
	}

	if _, err := update(func(u *Target) {
		u.AccessLevels[0].Grants = json.RawMessage(`{"roles":["LEDGER_RO_ROLE","LEDGER_RW_ROLE"]}`)
	}); slug(err) != "widening-not-allowed" {
		t.Errorf("widening: %v", err)
	}
	r, err = update(func(u *Target) { u.AccessLevels[1].Grants = json.RawMessage(`{"roles":["LEDGER_RO_ROLE"]}`) })
	if err == nil && len(r.Sides) != 2 {
		t.Errorf("narrowing sides %+v", r.Sides)
	}
	approved(t, s, r, err)
	revision++
	if queued(t, owner, write) != 0 || queued(t, owner, read) != -1 {
		t.Errorf("after the narrowing: write %d, read %d", queued(t, owner, write), queued(t, owner, read))
	}
	var snapshot string
	if err := owner.QueryRow(ctx, "select snapshot::text from audit_log where change_request_id = $1 and action = 'TARGET_UPDATED'", r.ID).
		Scan(&snapshot); err != nil || snapshot != `{"changed": null, "addedLevels": null, "narrowedLevels": ["write"]}` {
		t.Errorf("TARGET_UPDATED %s (%v)", snapshot, err)
	}
	tg.AccessLevels[1].Grants = json.RawMessage(`{"roles":["LEDGER_RO_ROLE"]}`)

	r, err = update(func(u *Target) {
		u.AccessLevels = append(u.AccessLevels, AccessLevel{Name: "admin", Grants: json.RawMessage(`{"roles":["LEDGER_RW_ROLE"]}`)})
	})
	approved(t, s, r, err)
	revision++
	if queued(t, owner, read) != -1 {
		t.Error("a new level queued a binding")
	}
	tg.AccessLevels = append(tg.AccessLevels, AccessLevel{Name: "admin", Grants: json.RawMessage(`{"roles":["LEDGER_RW_ROLE"]}`)})

	if _, err := s.SetLevelState(ctx, alice, tg.Metadata.Name, "read", "retire", revision, "", nil); slug(err) != "resource-in-use" {
		t.Errorf("retire a level in use: %v", err)
	}
	r, err = s.SetLevelState(ctx, alice, tg.Metadata.Name, "read", "deprecate", revision, "", nil)
	if err == nil && len(r.Sides) != 1 {
		t.Errorf("deprecation sides %+v", r.Sides)
	}
	approved(t, s, r, err)
	revision++
	tg.AccessLevels[0].State = "DEPRECATED"

	r, err = update(func(u *Target) {
		u.Definition = json.RawMessage(`{"schema":"LEDGER_APP","serviceName":"LEDGER2.prod.internal"}`)
	})
	approved(t, s, r, err)
	revision++
	if queued(t, owner, read) != 1 || queued(t, owner, write) != 0 {
		t.Errorf("after a new definition: read %d, write %d", queued(t, owner, read), queued(t, owner, write))
	}
	var state string
	var rev int64
	if err := owner.QueryRow(ctx, `select l.state, t.revision from target_access_levels l join targets t on t.id = l.target_id
		where t.id = $1 and l.name = 'read'`, id).Scan(&state, &rev); err != nil || state != "DEPRECATED" || rev != revision {
		t.Errorf("read %s, revision %d (%v)", state, rev, err)
	}
	rows, _ := owner.Query(ctx, "select action from audit_log where resource_type = 'TARGET' and resource_id = $1 and action like 'ACCESS_LEVEL_%'", id)
	actions, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	if len(actions) != 1 || actions[0] != "ACCESS_LEVEL_DEPRECATED" {
		t.Errorf("audit %v", actions)
	}
}

// TestTargetStates: a target without bindings can be retired, and is then
// final.
func TestTargetStates(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	tg := ledger()
	unique(t, owner, &tg)
	r, err := s.Create(ctx, alice, body(t, tg))
	approved(t, s, r, err)
	if _, err := s.SetState(ctx, eve, tg.Metadata.Name, "deprecate", 1, "", nil); slug(err) != "not-found" {
		t.Errorf("caller without a role: %v", err)
	}
	r, err = s.SetState(ctx, alice, tg.Metadata.Name, "retire", 1, "", nil)
	approved(t, s, r, err)
	if _, err := s.SetState(ctx, alice, tg.Metadata.Name, "reactivate", 2, "", nil); slug(err) != "not-found" {
		t.Errorf("a retired target is final: %v", err)
	}
}
