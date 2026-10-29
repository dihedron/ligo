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
