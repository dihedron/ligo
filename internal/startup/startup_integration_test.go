//go:build integration

package startup

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/sources"
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

// env holds the pools, a unique suffix x and the example configuration;
// the checks scan the whole database, so tests assert only on rows named
// with x.
type env struct {
	app, owner *pgxpool.Pool
	x          string
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
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
	v := &env{app: pools.App, owner: owner, x: uuid.NewV7().String()[24:]}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from change_requests where resource_name like $1", "%"+v.x)
		_, _ = owner.Exec(ctx, "delete from bindings where name like $1", "%"+v.x)
		_, _ = owner.Exec(ctx, "delete from target_access_levels where target_id in (select id from targets where name like $1)", "%"+v.x)
		_, _ = owner.Exec(ctx, "delete from targets where name like $1", "%"+v.x)
		_, _ = owner.Exec(ctx, "delete from sources where name like $1", "%"+v.x)
	})
	return v
}

func (v *env) checks(t *testing.T) *Checks {
	t.Helper()
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := sources.NewRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &Checks{DB: v.app, Config: cfg, ConfigSHA256: strings.Repeat("c", 64), Extractors: maps.Clone(rules.Extractors),
		Logger: slog.New(slog.DiscardHandler)}
	c.policy = cfg.Policy()
	return c
}

func (v *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := v.owner.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (v *env) source(t *testing.T, name, scope, td string) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	v.exec(t, `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by) values ($1, $2, $3, $4, $5, 't', 't')`,
		id, name, scope, td, `^spiffe://`+strings.ReplaceAll(td, ".", `\.`)+`/ns/`+v.x+`/sa/w$`)
	return id
}

func (v *env) target(t *testing.T, name, platform, scope, platformScope string) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	v.exec(t, `insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, created_by, updated_by)
		values ($1, $2, $3, 'oracle.v1', 'prod', $4, $5, '{}', 't', 't')`, id, name, platform, scope, platformScope)
	v.exec(t, `insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{}', '[]')`, id)
	return id
}

// binding inserts a binding on oracle-prod with the given store instance
// and scopes.
func (v *env) binding(t *testing.T, name string, src, tgt uuid.UUID, store string, scopes [3]string) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	v.exec(t, `insert into bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
		identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
		source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision, source_trust_domain, source_svid_regex,
		requested_spec, created_by, updated_by)
		values ($1, $2, $3, $4, 'read', 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', $5, 'vault-static',
		'bnd_' || left(md5($1::uuid::text), 16), $6, $7, $8, $9, 1, 1, 'prod.internal', '^spiffe://prod\.internal/x$', '{}', 't', 't')`,
		id, name, src, tgt, store, scopes[0], scopes[1], scopes[2], "ligo:apply:"+id.String()+":r1:a1")
	return id
}

// request inserts a pending change request on a binding (id may be nil for
// a CREATE) whose payload names its source.
func (v *env) request(t *testing.T, name, op string, id *uuid.UUID, source string) uuid.UUID {
	t.Helper()
	cr := uuid.NewV7()
	payload, _ := json.Marshal(map[string]string{"name": name, "source": source})
	var revision *int64
	if op != "CREATE" {
		one := int64(1)
		revision = &one
	}
	err := pgx.BeginFunc(context.Background(), v.owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `insert into change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent, zone,
		source_scope, target_scope, platform_scope, policy_sha256, distinct_approvers_required, payload, payload_sha256, requested_by, expires_at,
		expected_revision) values ($1, 'BINDING', $2, $3, $4, 'STANDARD', 'ALL', 'prod', 'dc/corp-prod', 'dc/corp-prod', 'dc/corp-prod', repeat('a', 64), true,
		$5, repeat('b', 64), 'carla', now() + interval '1 day', $6)`, cr, name, id, op, payload, revision); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `insert into change_request_sides (change_request_id, side, scope, approval_required, basis, requested_by, cr_kind)
			values ($1, 'TARGET', 'dc/corp-prod', true, 'HUMAN', 'carla', 'STANDARD')`, cr)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return cr
}

// audited returns the snapshots of the entries with action written after
// audit id after.
func (v *env) audited(t *testing.T, after int64, action string) []string {
	t.Helper()
	rows, err := v.owner.Query(context.Background(), "select snapshot::text from audit_log where id > $1 and action = $2 order by id", after, action)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (v *env) lastAudit(t *testing.T) int64 {
	t.Helper()
	var id int64
	if err := v.owner.QueryRow(context.Background(), "select coalesce(max(id), 0) from audit_log").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestConfigLoaded: every start audits the configuration and the policy;
// a changed policy is audited with its changes, a weaker one also as
// weakened (§8.2 step 2).
func TestConfigLoaded(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	c := v.checks(t)
	before := v.lastAudit(t)
	if err := c.configLoaded(ctx); err != nil {
		t.Fatal(err)
	}
	loaded := v.audited(t, before, "CONFIG_LOADED")
	if len(loaded) != 1 || !strings.Contains(loaded[0], c.policy.SHA256()) || !strings.Contains(loaded[0], `"requiredScopes"`) {
		t.Fatalf("CONFIG_LOADED: %v", loaded)
	}
	if err := c.configLoaded(ctx); err != nil || len(v.audited(t, before, "CONFIG_GOVERNANCE_POLICY_CHANGED")) != 0 {
		t.Errorf("same policy reported as changed (%v)", err)
	}

	c.Config.Authorization.Approval.RequiredScopes = c.Config.Authorization.Approval.RequiredScopes[1:]
	c.policy = c.Config.Policy()
	if err := c.configLoaded(ctx); err != nil {
		t.Fatal(err)
	}
	changed, weakened := v.audited(t, before, "CONFIG_GOVERNANCE_POLICY_CHANGED"), v.audited(t, before, "CONFIG_APPROVAL_POLICY_WEAKENED")
	if len(changed) != 1 || !strings.Contains(changed[0], `"field": "requiredScopes"`) || len(weakened) != 1 ||
		!strings.Contains(weakened[0], "removed from required_scopes") {
		t.Errorf("changed %v, weakened %v", changed, weakened)
	}
	// the next start compares with the weaker policy: stricter again is a change, not a weakening
	c = v.checks(t)
	if err := c.configLoaded(ctx); err != nil || len(v.audited(t, before, "CONFIG_GOVERNANCE_POLICY_CHANGED")) != 2 ||
		len(v.audited(t, before, "CONFIG_APPROVAL_POLICY_WEAKENED")) != 1 {
		t.Errorf("stricter policy (%v)", err)
	}
}

// TestOrphans: rule 10 fails on references to platforms and instances no
// longer configured, and on strategies a store no longer declares, unless
// --allow-orphaned-bindings, which audits them.
func TestOrphans(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	src := v.source(t, "src-"+x, "dc/corp-prod", "prod.internal")
	v.target(t, "gone-"+x, "gone-platform-"+x, "dc/corp-prod", "dc/corp-prod")
	tgt := v.target(t, "tgt-"+x, "oracle-prod", "dc/corp-prod", "dc/corp-prod")
	v.binding(t, "b-"+x, src, tgt, "vault-gone-"+x, [3]string{"dc/corp-prod", "dc/corp-prod", "dc/corp-prod"})

	c := v.checks(t)
	err := c.orphans(ctx)
	if err == nil || !strings.Contains(err.Error(), "target gone-"+x+": platform gone-platform-"+x) ||
		!strings.Contains(err.Error(), "binding b-"+x+": vault.v1 instance vault-gone-"+x) {
		t.Fatalf("orphans: %v", err)
	}
	none := func(string) []string { return nil }
	if err := c.Strategies(ctx, none); err == nil || !strings.Contains(err.Error(), "vault.v1 no longer declares strategy vault-static") {
		t.Errorf("strategies: %v", err)
	}
	if err := c.Strategies(ctx, func(string) []string { return []string{"vault-static", "vault-dynamic"} }); err != nil &&
		strings.Contains(err.Error(), "vault.v1") {
		t.Errorf("declared strategy refused: %v", err)
	}

	c.AllowOrphanedBindings = true
	before := v.lastAudit(t)
	if err := c.orphans(ctx); err != nil {
		t.Fatal(err)
	}
	if got := v.audited(t, before, "SYSTEM_ORPHANED_BINDINGS"); len(got) != 1 || !strings.Contains(got[0], "vault-gone-"+x) {
		t.Errorf("orphans audited: %v", got)
	}
}

// TestScopes: rule 17 refuses drifted scopes, re-scopes them with
// --accept-scope-changes (sources, targets' platform scope, stale binding
// copies) and fails the pending requests concerned; an unresolvable
// source is fatal even with the flag.
func TestScopes(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	td := "st" + x + ".internal"
	c := v.checks(t)
	moved, err := governance.NewStaticExtractor("lab/st" + x + "/moved")
	if err != nil {
		t.Fatal(err)
	}
	c.Extractors[td] = moved

	src := v.source(t, "src-"+x, "lab/st"+x, td)
	tgt := v.target(t, "tgt-"+x, "oracle-prod", "dc/corp-prod/st"+x, "dc/old"+x)
	b := v.binding(t, "b-"+x, src, tgt, "vault-prod", [3]string{"lab/st" + x, "dc/corp-prod/st" + x, "dc/old" + x})
	other := v.target(t, "tgt2-"+x, "oracle-prod", "dc/corp-prod/st"+x, "dc/corp-prod")
	stale := v.binding(t, "b2-"+x, v.source(t, "src2-"+x, "dc/corp-prod", "prod.internal"), other, "vault-prod",
		[3]string{"dc/corp-prod", "dc/corp-prod/elsewhere" + x, "dc/corp-prod"})
	update := v.request(t, "b-"+x, "UPDATE", &b, "src-"+x)
	create := v.request(t, "new-"+x, "CREATE", nil, "src-"+x)

	err = c.scopes(ctx)
	if err == nil || !strings.Contains(err.Error(), "source src-"+x+": lab/st"+x+" to lab/st"+x+"/moved") ||
		!strings.Contains(err.Error(), "target tgt-"+x+": platform scope dc/old"+x+" to dc/corp-prod") {
		t.Fatalf("drift without the flag: %v", err)
	}

	c.AcceptScopeChanges = true
	before := v.lastAudit(t)
	if err := c.scopes(ctx); err != nil {
		t.Fatal(err)
	}
	var scopes, staleScopes []string
	if err := v.owner.QueryRow(ctx, "select array[source_scope, target_scope, platform_scope]::text[] from bindings where id = $1", b).Scan(&scopes); err != nil ||
		strings.Join(scopes, ",") != "lab/st"+x+"/moved,dc/corp-prod/st"+x+",dc/corp-prod" {
		t.Errorf("binding scopes %v (%v)", scopes, err)
	}
	if err := v.owner.QueryRow(ctx, "select array[source_scope, target_scope, platform_scope]::text[] from bindings where id = $1", stale).Scan(&staleScopes); err != nil ||
		staleScopes[1] != "dc/corp-prod/st"+x {
		t.Errorf("stale binding scopes %v (%v)", staleScopes, err)
	}
	for _, cr := range []uuid.UUID{update, create} {
		var status, applyError string
		if err := v.owner.QueryRow(ctx, "select status, coalesce(apply_error, '') from change_requests where id = $1", cr).Scan(&status, &applyError); err != nil ||
			status != "FAILED_TO_APPLY" || applyError != "re-scoped" {
			t.Errorf("request %s: %s %q (%v)", cr, status, applyError, err)
		}
	}
	for action, n := range map[string]int{"SOURCE_RESCOPED": 1, "TARGET_RESCOPED": 1, "BINDING_RESCOPED": 3, "CR_APPLY_FAILED": 2} {
		var count int
		if err := v.owner.QueryRow(ctx, "select count(*) from audit_log where id > $1 and action = $2 and (resource_name like $3 or action = 'CR_APPLY_FAILED')",
			before, action, "%"+x).Scan(&count); err != nil || count < n {
			t.Errorf("%s: %d audited, want %d (%v)", action, count, n, err)
		}
	}
	if err := c.scopes(ctx); err != nil {
		t.Errorf("a second start still drifts: %v", err)
	}

	v.source(t, "lost-"+x, "lab/lost"+x, "lost"+x+".internal")
	if err := c.scopes(ctx); err == nil || !strings.Contains(err.Error(), "source lost-"+x+": its regex resolves to no scope") {
		t.Errorf("unresolvable source: %v", err)
	}
}

// TestNamesAndInterconnects: a name prefix that no longer resolves for an
// existing scope is fatal (rule 16); bindings the policy now denies are
// audited, never changed (rule 18).
func TestNamesAndInterconnects(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	c := v.checks(t)
	tgt := v.target(t, "tgt-"+x, "oracle-prod", "dc/corp-prod/n"+x, "dc/corp-prod")
	if err := c.names(ctx); err != nil && strings.Contains(err.Error(), x) {
		t.Fatalf("names: %v", err)
	}
	c.Config.Governance.NamePrefixes = append([]governance.NamePrefix{{Scopes: []string{"dc/corp-prod/n" + x}, Prefix: "{5}-"}},
		c.Config.Governance.NamePrefixes...)
	if err := c.names(ctx); err == nil || !strings.Contains(err.Error(), "target scope dc/corp-prod/n"+x) {
		t.Errorf("unresolvable prefix: %v", err)
	}

	src := v.source(t, "src-"+x, "dc/corp-test", "test.internal")
	v.binding(t, "b-"+x, src, tgt, "vault-prod", [3]string{"dc/corp-test", "dc/corp-prod/n" + x, "dc/corp-prod"})
	before := v.lastAudit(t)
	if err := c.interconnects(ctx); err != nil {
		t.Fatal(err)
	}
	got := v.audited(t, before, "SYSTEM_INTERCONNECT_VIOLATIONS")
	if len(got) != 1 || !strings.Contains(got[0], `"binding": "b-`+x+`"`) || !strings.Contains(got[0], "no-test-to-prod") {
		t.Errorf("violations: %v", got)
	}
}

// TestWiring: a binding whose wiring differs from its platform's keeps it,
// with a warning (rule 11).
func TestWiring(t *testing.T) {
	v := setup(t)
	x := v.x
	c := v.checks(t)
	var logs bytes.Buffer
	c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	src := v.source(t, "src-"+x, "dc/corp-prod", "prod.internal")
	tgt := v.target(t, "tgt-"+x, "oracle-prod", "dc/corp-prod", "dc/corp-prod")
	v.binding(t, "b-"+x, src, tgt, "vault-test", [3]string{"dc/corp-prod", "dc/corp-prod", "dc/corp-prod"})
	v.binding(t, "same-"+x, v.source(t, "src2-"+x, "dc/corp-prod", "prod.internal"), tgt, "vault-prod", [3]string{"dc/corp-prod", "dc/corp-prod", "dc/corp-prod"})
	if err := c.wiring(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "binding=b-"+x) || strings.Contains(logs.String(), "binding=same-"+x) {
		t.Errorf("warnings: %s", logs.String())
	}
}
