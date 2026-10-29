//go:build integration

package catalog

import (
	"context"
	"errors"
	"os"
	"slices"
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

func example(t *testing.T) *config.Config {
	t.Helper()
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func setup(t *testing.T) (*Reader, *pgxpool.Pool, string) {
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
	x := uuid.NewV7().String()[24:]
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from change_requests where resource_name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from bindings where name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from target_access_levels where target_id in (select id from targets where name like $1)", "%"+x)
		_, _ = owner.Exec(ctx, "delete from targets where name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from sources where name like $1", "%"+x)
	})
	return &Reader{DB: pools.App, Policy: example(t).Policy()}, owner, x
}

func exec(t *testing.T, o *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := o.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func target(t *testing.T, o *pgxpool.Pool, name, scope, vis, to string) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	exec(t, o, `insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, visibility, visible_to, created_by, updated_by)
		values ($1, $2, 'oracle-prod', 'oracle.v1', 'prod', $3, 'dc/corp-prod', '{}', $4, $5::jsonb, 't', 't')`, id, name, scope, vis, to)
	exec(t, o, `insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{}', '[]')`, id)
	return id
}

func source(t *testing.T, o *pgxpool.Pool, name, scope, td, regex string) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	exec(t, o, `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by)
		values ($1, $2, $3, $4, $5, 't', 't')`, id, name, scope, td, regex)
	return id
}

func names(ts []Target) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func isNotFound(err error) bool {
	e := (*changerequests.Error)(nil)
	return errors.As(err, &e) && e.Status == 404
}

// TestAC72: the catalog lists the visible targets the policy lets the
// caller request; a target fetched by name needs only to be visible.
func TestAC72(t *testing.T) {
	r, o, x := setup(t)
	ctx := context.Background()
	a, b, c := "a-"+x, "b-"+x, "c-"+x
	target(t, o, a, "dc/corp-prod/ledger", "PRIVATE", "[]")
	target(t, o, b, "dc/corp-prod/ledger", "LISTED", `["cloud/fin-01/*"]`)
	target(t, o, c, "dc/corp-prod/ledger", "PUBLIC", "[]")
	source(t, o, "fin-01-test-web-s-"+x, "cloud/fin-01-test/web", "cloud.internal", `^spiffe://cloud\.internal/acct/fin-01-test/tenant/web/sa/`+x+`$`)
	payments := caller("pia", config.RoleOperator, "cloud/fin-01/payments")
	tester := caller("teo", config.RoleOperator, "cloud/fin-01-test/web")
	platform := caller("pam", config.RoleViewer, "dc/corp-prod")
	viewer := caller("vic", config.RoleViewer, "cloud/fin-01/payments")

	for _, tc := range []struct {
		c    changerequests.Caller
		want []string
	}{
		{payments, []string{b, c}},
		{tester, nil},                 // B is not listed to it; C is denied by no-test-to-prod
		{platform, []string{a, b, c}}, // owners see their targets regardless
		{viewer, nil},                 // can request nothing
	} {
		got, err := r.Targets(ctx, tc.c, Query{Q: x})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names(got), tc.want) {
			t.Errorf("%s: catalog %v, want %v", tc.c.ID(), names(got), tc.want)
		}
	}
	if _, err := r.Target(ctx, payments, a); !isNotFound(err) {
		t.Errorf("PRIVATE A: %v", err)
	}
	for _, n := range []string{b, c} {
		if _, err := r.Target(ctx, payments, n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	out, err := r.Outcomes(ctx, tester, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Allowed || out[0].Rule != "no-test-to-prod" {
		t.Errorf("tester's outcome for C: %+v", out)
	}
	if got, _ := r.Targets(ctx, payments, Query{Q: x, AfterName: b}); !slices.Equal(names(got), []string{c}) {
		t.Errorf("after %s: %v", b, names(got))
	}
}

// TestAC59: a binding and its change requests are visible from any of its
// three scopes and from its parties' scopes, and to nobody else.
func TestAC59(t *testing.T) {
	r, o, x := setup(t)
	ctx := context.Background()
	src := source(t, o, "fin-01-payments-s-"+x, "cloud/fin-01/payments", "cloud.internal", `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/`+x+`$`)
	tgt := target(t, o, "ledger-"+x, "dc/corp-prod/ledger", "PRIVATE", "[]")
	binding, name, cr := uuid.NewV7(), "fin-01-payments-b-"+x, uuid.NewV7()
	exec(t, o, `insert into bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
		identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
		source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision,
		source_trust_domain, source_svid_regex, requested_spec, created_by, updated_by)
		values ($1, $2, $3, $4, 'read', 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', 'vault-prod', 'vault-static',
		'bnd_' || left(md5($1::uuid::text), 16), 'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod', $5, 1, 1, 'cloud.internal',
		'^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/x$', '{}', 't', 't')`, binding, name, src, tgt, "ligo:apply:"+binding.String()+":r1:a1")
	err := pgx.BeginFunc(ctx, o, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent, zone,
			source_scope, target_scope, platform_scope, interconnect_rule, policy_sha256, distinct_approvers_required, payload, payload_sha256,
			requested_by, expires_at) values ($1, 'BINDING', $2, $3, 'CREATE', 'STANDARD', 'ALL', 'prod', 'cloud/fin-01/payments',
			'dc/corp-prod/ledger', 'dc/corp-prod', 'cloud-to-dc', repeat('a', 64), true, '{}', repeat('b', 64), 'carla', now() + interval '1 day')`,
			cr, name, binding); err != nil {
			return err
		}
		for _, sd := range []struct{ side, scope string }{{"TARGET", "dc/corp-prod/ledger"}, {"SOURCE", "cloud/fin-01/payments"}, {"PARTY:security", "sec/infosec"}} {
			if _, err := tx.Exec(ctx, `insert into change_request_sides (change_request_id, side, scope, approval_required, basis, requested_by, cr_kind)
				values ($1, $2, $3, true, 'HUMAN', 'carla', 'STANDARD')`, cr, sd.side, sd.scope); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	requests := &changerequests.Service{DB: r.DB}
	for _, tc := range []struct {
		c       changerequests.Caller
		visible bool
	}{
		{caller("v1", config.RoleViewer, "cloud/fin-01/payments"), true},
		{caller("v2", config.RoleViewer, "dc/corp-prod/ledger"), true},
		{caller("v3", config.RoleViewer, "dc/corp-prod"), true},
		{caller("sara", config.RoleApprover, "sec/infosec"), true},
		{caller("v5", config.RoleViewer, "cloud/fin-02/*"), false},
	} {
		_, err := r.Binding(ctx, tc.c, name)
		if tc.visible != (err == nil) || !tc.visible && !isNotFound(err) {
			t.Errorf("%s: binding %v", tc.c.ID(), err)
		}
		_, err = requests.Get(ctx, tc.c, cr)
		if tc.visible != (err == nil) || !tc.visible && !isNotFound(err) {
			t.Errorf("%s: change request %v", tc.c.ID(), err)
		}
	}
}
