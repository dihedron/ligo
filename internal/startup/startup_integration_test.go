//go:build integration

package startup

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/instances"
	"github.com/dihedron/ligo/internal/metrics"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	dto "github.com/prometheus/client_model/go"
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
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), store.Limits{}, insecure)
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
		_, _ = owner.Exec(ctx, "delete from target_network_flows where target_id in (select id from targets where name like $1)", "%"+v.x)
		_, _ = owner.Exec(ctx, "delete from targets where name like $1", "%"+v.x)
		_, _ = owner.Exec(ctx, "delete from sources where name like $1", "%"+v.x)
		_, _ = owner.Exec(ctx, "delete from accounts where name like $1", "%"+v.x)
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
	set, err := instances.LoadManifest("../../examples/instances.yaml")
	if err != nil {
		t.Fatal(err)
	}
	inst := instances.Fixed{Set: set}
	rules, err := sources.NewRules(cfg, inst)
	if err != nil {
		t.Fatal(err)
	}
	c := &Checks{DB: v.app, Config: cfg, ConfigSHA256: strings.Repeat("c", 64), ThemeSHA256: map[string]string{"logo": strings.Repeat("d", 64)}, Extractors: maps.Clone(rules.Extractors),
		Instances: inst, Logger: slog.New(slog.DiscardHandler)}
	c.policy = cfg.Policy()
	return c
}

// setPlatform changes the platform called name in c's instances.
func setPlatform(c *Checks, name string, f func(*instances.Definition)) {
	set := c.Instances.Current()
	cur, _ := set.Platform(name)
	p := *cur
	f(&p)
	c.Instances = instances.Fixed{Set: set.With(&p)}
}

func (v *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := v.owner.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (v *env) source(t *testing.T, name, jurisdiction, td string) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	v.exec(t, `insert into sources (id, name, jurisdiction, trust_domain, svid_regex, created_by, updated_by) values ($1, $2, $3, $4, $5, 't', 't')`,
		id, name, jurisdiction, td, `^spiffe://`+strings.ReplaceAll(td, ".", `\.`)+`/ns/`+v.x+`/sa/w$`)
	return id
}

func (v *env) target(t *testing.T, name, platform, jurisdiction, platformJurisdiction string) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	v.exec(t, `insert into targets (id, name, platform, platform_type, realm, jurisdiction, platform_jurisdiction, definition, created_by, updated_by)
		values ($1, $2, $3, 'oracle.v1', 'prod', $4, $5, '{}', 't', 't')`, id, name, platform, jurisdiction, platformJurisdiction)
	v.exec(t, `insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{}', '[]')`, id)
	return id
}

// binding inserts a binding on oracle-prod with the given store instance
// and jurisdictions.
func (v *env) binding(t *testing.T, name string, src, tgt uuid.UUID, store string, jurisdictions [3]string) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	v.exec(t, `insert into bindings (id, name, source_id, target_id, access_level, realm, platform_type, platform,
		identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
		source_jurisdiction, target_jurisdiction, platform_jurisdiction, workflow_id, source_revision, target_revision, source_trust_domain, source_svid_regex,
		requested_spec, created_by, updated_by)
		values ($1, $2, $3, $4, 'read', 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', $5, 'vault-static',
		'bnd_' || left(md5($1::uuid::text), 16), $6, $7, $8, $9, 1, 1, 'prod.internal', '^spiffe://prod\.internal/x$', '{}', 't', 't')`,
		id, name, src, tgt, store, jurisdictions[0], jurisdictions[1], jurisdictions[2], "ligo:apply:"+id.String()+":r1:a1")
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
		if _, err := tx.Exec(context.Background(), `insert into change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent, realm,
		source_jurisdiction, target_jurisdiction, platform_jurisdiction, policy_sha256, distinct_approvers_required, payload, payload_sha256, requested_by, expires_at,
		expected_revision) values ($1, 'BINDING', $2, $3, $4, 'STANDARD', 'ALL', 'prod', 'dc/corp-prod', 'dc/corp-prod', 'dc/corp-prod', repeat('a', 64), true,
		$5, repeat('b', 64), 'carla', now() + interval '1 day', $6)`, cr, name, id, op, payload, revision); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `insert into change_request_sides (change_request_id, side, jurisdiction, approval_required, basis, requested_by, cr_kind)
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
	if len(loaded) != 1 || !strings.Contains(loaded[0], c.policy.SHA256()) || !strings.Contains(loaded[0], `"requiredJurisdictions"`) ||
		!strings.Contains(loaded[0], `"themeSha256": {"logo": "`+strings.Repeat("d", 64)+`"}`) {
		t.Fatalf("CONFIG_LOADED: %v", loaded)
	}
	before = v.lastAudit(t) // the first load compared with whatever started last, maybe another test's configuration
	if err := c.configLoaded(ctx); err != nil || len(v.audited(t, before, "CONFIG_CHARTER_CHANGED")) != 0 {
		t.Errorf("same policy reported as changed (%v)", err)
	}

	c.Config.Authorization.Approval.RequiredJurisdictions = c.Config.Authorization.Approval.RequiredJurisdictions[1:]
	c.policy = c.Config.Policy()
	if err := c.configLoaded(ctx); err != nil {
		t.Fatal(err)
	}
	changed, weakened := v.audited(t, before, "CONFIG_CHARTER_CHANGED"), v.audited(t, before, "CONFIG_APPROVAL_POLICY_WEAKENED")
	if len(changed) != 1 || !strings.Contains(changed[0], `"field": "requiredJurisdictions"`) || len(weakened) != 1 ||
		!strings.Contains(weakened[0], "removed from required_jurisdictions") {
		t.Errorf("changed %v, weakened %v", changed, weakened)
	}
	// the next start compares with the weaker policy: stricter again is a change, not a weakening
	c = v.checks(t)
	if err := c.configLoaded(ctx); err != nil || len(v.audited(t, before, "CONFIG_CHARTER_CHANGED")) != 2 ||
		len(v.audited(t, before, "CONFIG_APPROVAL_POLICY_WEAKENED")) != 1 {
		t.Errorf("stricter policy (%v)", err)
	}
}

// TestStrategies: the part of rule 10 left at startup fails on strategies a
// store type no longer declares, unless --allow-orphaned-bindings, which
// audits them; references to platforms and instances are kept by the
// instances themselves (.specs/ligo-instances.md §6 rule 9).
func TestStrategies(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	src := v.source(t, "src-"+x, "dc/corp-prod", "prod.internal")
	tgt := v.target(t, "tgt-"+x, "oracle-prod", "dc/corp-prod", "dc/corp-prod")
	v.binding(t, "b-"+x, src, tgt, "vault-prod", [3]string{"dc/corp-prod", "dc/corp-prod", "dc/corp-prod"})

	c := v.checks(t)
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
	if err := c.Strategies(ctx, none); err != nil {
		t.Fatal(err)
	}
	if got := v.audited(t, before, "SYSTEM_ORPHANED_BINDINGS"); len(got) != 1 || !strings.Contains(got[0], "vault-static") {
		t.Errorf("audited: %v", got)
	}
}

// TestUnknownPlatforms: a role binding scoped to a platform that does not
// exist is a warning, not an error (.specs/ligo-instances.md §3 rule 3).
func TestUnknownPlatforms(t *testing.T) {
	v := setup(t)
	c := v.checks(t)
	var logs bytes.Buffer
	c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	c.Config.Authorization.Bindings = append(c.Config.Authorization.Bindings, config.RoleBinding{SPIFFEID: "spiffe://prod.internal/x",
		Role: config.RoleTrustedAutomation, Jurisdictions: []string{"dc/*"}, Platforms: []string{"oracle-prod", "gone-" + v.x}})
	if err := c.unknownPlatforms(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "platform=gone-"+v.x) || strings.Contains(logs.String(), "platform=oracle-prod") {
		t.Errorf("warnings: %s", logs.String())
	}
}

// TestJurisdictions: rule 17 refuses drifted jurisdictions, transfers them with
// --accept-jurisdiction-changes (sources, targets' platform jurisdiction, stale binding
// copies) and fails the pending requests concerned; an unresolvable
// source is fatal even with the flag.
func TestJurisdictions(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	td := "st" + x + ".internal"
	c := v.checks(t)
	moved, err := charter.NewStaticExtractor("lab/st" + x + "/moved")
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

	err = c.jurisdictions(ctx)
	if err == nil || !strings.Contains(err.Error(), "source src-"+x+": lab/st"+x+" to lab/st"+x+"/moved") ||
		!strings.Contains(err.Error(), "target tgt-"+x+": platform jurisdiction dc/old"+x+" to dc/corp-prod") {
		t.Fatalf("drift without the flag: %v", err)
	}

	c.AcceptJurisdictionChanges = true
	before := v.lastAudit(t)
	if err := c.jurisdictions(ctx); err != nil {
		t.Fatal(err)
	}
	var jurisdictions, staleJurisdictions []string
	if err := v.owner.QueryRow(ctx, "select array[source_jurisdiction, target_jurisdiction, platform_jurisdiction]::text[] from bindings where id = $1", b).Scan(&jurisdictions); err != nil ||
		strings.Join(jurisdictions, ",") != "lab/st"+x+"/moved,dc/corp-prod/st"+x+",dc/corp-prod" {
		t.Errorf("binding jurisdictions %v (%v)", jurisdictions, err)
	}
	if err := v.owner.QueryRow(ctx, "select array[source_jurisdiction, target_jurisdiction, platform_jurisdiction]::text[] from bindings where id = $1", stale).Scan(&staleJurisdictions); err != nil ||
		staleJurisdictions[1] != "dc/corp-prod/st"+x {
		t.Errorf("stale binding jurisdictions %v (%v)", staleJurisdictions, err)
	}
	for _, cr := range []uuid.UUID{update, create} {
		var status, applyError string
		if err := v.owner.QueryRow(ctx, "select status, coalesce(apply_error, '') from change_requests where id = $1", cr).Scan(&status, &applyError); err != nil ||
			status != "FAILED_TO_APPLY" || applyError != "transferred" {
			t.Errorf("request %s: %s %q (%v)", cr, status, applyError, err)
		}
	}
	for action, n := range map[string]int{"SOURCE_TRANSFERRED": 1, "TARGET_TRANSFERRED": 1, "BINDING_TRANSFERRED": 3, "CR_APPLY_FAILED": 2} {
		var count int
		if err := v.owner.QueryRow(ctx, "select count(*) from audit_log where id > $1 and action = $2 and (resource_name like $3 or action = 'CR_APPLY_FAILED')",
			before, action, "%"+x).Scan(&count); err != nil || count < n {
			t.Errorf("%s: %d audited, want %d (%v)", action, count, n, err)
		}
	}
	if err := c.jurisdictions(ctx); err != nil {
		t.Errorf("a second start still drifts: %v", err)
	}

	v.source(t, "lost-"+x, "lab/lost"+x, "lost"+x+".internal")
	if err := c.jurisdictions(ctx); err == nil || !strings.Contains(err.Error(), "source lost-"+x+": its regex resolves to no jurisdiction") {
		t.Errorf("unresolvable source: %v", err)
	}
}

// TestNamesAndInterconnects: a name prefix that no longer resolves for an
// existing jurisdiction is fatal (rule 16); bindings the policy now denies are
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
	c.Config.Charter.NamePrefixes = append([]charter.NamePrefix{{Jurisdictions: []string{"dc/corp-prod/n" + x}, Prefix: "{5}-"}},
		c.Config.Charter.NamePrefixes...)
	if err := c.names(ctx); err == nil || !strings.Contains(err.Error(), "target jurisdiction dc/corp-prod/n"+x) {
		t.Errorf("unresolvable prefix: %v", err)
	}

	if err := c.interconnects(ctx); err != nil {
		t.Fatal(err)
	}
	gauge := func() float64 { // AC-58: ligo_interconnect_violations
		var d dto.Metric
		if err := metrics.InterconnectViolations.Write(&d); err != nil {
			t.Fatal(err)
		}
		return d.GetGauge().GetValue()
	}
	violations := gauge()
	src := v.source(t, "src-"+x, "dc/corp-test", "test.internal")
	v.binding(t, "b-"+x, src, tgt, "vault-prod", [3]string{"dc/corp-test", "dc/corp-prod/n" + x, "dc/corp-prod"})
	before := v.lastAudit(t)
	if err := c.interconnects(ctx); err != nil {
		t.Fatal(err)
	}
	if gauge() != violations+1 {
		t.Errorf("ligo_interconnect_violations %v, was %v", gauge(), violations)
	}
	got := v.audited(t, before, "SYSTEM_INTERCONNECT_VIOLATIONS")
	if len(got) != 1 || !strings.Contains(got[0], `"binding": "b-`+x+`"`) || !strings.Contains(got[0], "no-test-to-prod") {
		t.Errorf("violations: %v", got)
	}
}

// TestBreakGlassParties: a party no break-glass policy covers is logged and
// audited at startup, and nothing is when every party is covered (rule 18).
func TestBreakGlassParties(t *testing.T) {
	v := setup(t)
	c := v.checks(t)
	var logs bytes.Buffer
	c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	c.policy.BreakGlassPolicies = []charter.BreakGlassPolicy{{Jurisdictions: []string{"dc/*"}}}
	c.policy.Interconnects.Rules = []charter.InterconnectRule{{Name: "gap-" + v.x,
		AdditionalApprovals: []charter.AdditionalApproval{{Name: "security", Jurisdiction: "sec/infosec"}}}}
	before := v.lastAudit(t)
	if err := c.breakGlassParties(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := v.audited(t, before, "SYSTEM_BREAK_GLASS_PARTY_UNCOVERED")
	if len(got) != 1 || !strings.Contains(got[0], "gap-"+v.x) || !strings.Contains(got[0], "sec/infosec") {
		t.Errorf("audited: %v", got)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "sec/infosec") {
		t.Errorf("logs: %s", logs.String())
	}
	c.policy.BreakGlassPolicies[0].Jurisdictions = append(c.policy.BreakGlassPolicies[0].Jurisdictions, "sec/*")
	before = v.lastAudit(t)
	if err := c.breakGlassParties(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := v.audited(t, before, "SYSTEM_BREAK_GLASS_PARTY_UNCOVERED"); len(got) != 0 {
		t.Errorf("covered: %v", got)
	}
}

// TestPlatforms: levels outside the current privilege bounds and flows
// outside the allowed endpoints are reported in one entry (rule 19).
func TestPlatforms(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	c := v.checks(t)

	tgt := v.target(t, "tgt-"+x, "oracle-prod", "dc/corp-prod", "dc/corp-prod")
	v.exec(t, `insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'admin', '{"roles":["DBA"]}', '["role:DBA"]')`, tgt)
	v.exec(t, `insert into target_network_flows (target_id, name, protocol, destination, ports, tls) values
		($1, 'ledger', 'TCP', 'ledger-db.prod.internal', '{[1522,1523)}', true), ($1, 'legacy', 'TCP', 'legacy.prod.internal', '{[1521,1522)}', false)`, tgt)
	prod, _ := c.Instances.Current().Platform("oracle-prod")
	bounds := prod.PrivilegeBounds()["grantableRoles"].([]string)
	validate := func(_ context.Context, req *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error) {
		var g struct {
			Roles []string `json:"roles"`
		}
		_ = json.Unmarshal(req.GetAccessLevels()[0].GetGrantsJson(), &g)
		for _, r := range g.Roles {
			if !slices.Contains(bounds, r) {
				return &pluginv1.ValidateTargetResponse{Errors: []string{r + " is not grantable"}}, nil
			}
		}
		return &pluginv1.ValidateTargetResponse{Valid: true}, nil
	}
	before := v.lastAudit(t)
	if err := c.Platforms(ctx, validate); err != nil {
		t.Fatal(err)
	}
	got := v.audited(t, before, "SYSTEM_PRIVILEGE_BOUND_VIOLATIONS")
	if len(got) != 1 || !strings.Contains(got[0], `"level": "admin"`) || !strings.Contains(got[0], "DBA is not grantable") ||
		!strings.Contains(got[0], `"flow": "legacy"`) || strings.Contains(got[0], `"level": "read"`) || strings.Contains(got[0], `"flow": "ledger"`) {
		t.Errorf("violations: %v", got)
	}
}

// Rule 17 for the account column: a change of the structure moves resources
// between accounts, only into registered ones and only with the flag.
func TestAccountDrift(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	account := "st" + x
	td := account + ".internal"
	c := v.checks(t)
	jurisdiction := "dc/corp-prod/" + account
	static, err := charter.NewStaticExtractor(jurisdiction)
	if err != nil {
		t.Fatal(err)
	}
	c.Extractors[td] = static
	src := v.source(t, "acs-"+x, jurisdiction, td)
	tgt := v.target(t, "act-"+x, "oracle-prod", jurisdiction, "dc/corp-prod")
	c.Config.Charter.Accounts = &charter.Accounts{Jurisdiction: "dc/corp-prod/{account}", SourceJurisdiction: "dc/corp-prod/{account}", TargetJurisdiction: "dc/corp-prod/{account}"}
	stored := func(table string, id uuid.UUID) string {
		t.Helper()
		var a string
		if err := v.owner.QueryRow(ctx, "select coalesce(account, '') from "+table+" where id = $1", id).Scan(&a); err != nil {
			t.Fatal(err)
		}
		return a
	}

	c.AcceptJurisdictionChanges = true
	if err := c.jurisdictions(ctx); err == nil || !strings.Contains(err.Error(), "source acs-"+x+`: account "`+account+`" of jurisdiction`) ||
		!strings.Contains(err.Error(), "target act-"+x+`: account "`+account+`" of jurisdiction`) || !strings.Contains(err.Error(), "register it") {
		t.Fatalf("an unregistered account, even with the flag: %v", err)
	}
	v.exec(t, "insert into accounts (name, registered_by) values ($1, 't')", account)
	c.AcceptJurisdictionChanges = false
	if err := c.jurisdictions(ctx); err == nil || !strings.Contains(err.Error(), "source acs-"+x+`: account "" to "`+account+`"`) {
		t.Fatalf("drift without the flag: %v", err)
	}
	c.AcceptJurisdictionChanges = true
	before := v.lastAudit(t)
	if err := c.jurisdictions(ctx); err != nil {
		t.Fatal(err)
	}
	if a, b := stored("sources", src), stored("targets", tgt); a != account || b != account {
		t.Errorf("accounts %q, %q", a, b)
	}
	var n int
	if err := v.owner.QueryRow(ctx, `select count(*) from audit_log where id > $1 and action in ('SOURCE_TRANSFERRED', 'TARGET_TRANSFERRED')
		and snapshot->>'column' = 'account' and snapshot->>'new' = $2`, before, account).Scan(&n); err != nil || n != 2 {
		t.Errorf("audited %d (%v)", n, err)
	}
	c.AcceptJurisdictionChanges = false
	if err := c.jurisdictions(ctx); err != nil {
		t.Errorf("settled: %v", err)
	}
	// the structure removed: the resources are no longer account-managed
	c.Config.Charter.Accounts = nil
	if err := c.jurisdictions(ctx); err == nil || !strings.Contains(err.Error(), `account "`+account+`" to ""`) {
		t.Fatalf("structure removed: %v", err)
	}
	c.AcceptJurisdictionChanges = true
	if err := c.jurisdictions(ctx); err != nil {
		t.Fatal(err)
	}
	if a := stored("sources", src); a != "" {
		t.Errorf("account %q", a)
	}
}

// Existing resources that do not fit the structure stop startup: no
// transfer can fix them.
func TestJurisdictionForm(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	account := "st" + x
	c := v.checks(t)
	td := account + ".internal"
	jurisdiction := "dc/corp-prod/" + account
	static, err := charter.NewStaticExtractor(jurisdiction)
	if err != nil {
		t.Fatal(err)
	}
	c.Extractors[td] = static
	v.exec(t, "insert into accounts (name, registered_by) values ($1, 't')", account)
	v.source(t, "fs-"+x, jurisdiction, td)
	v.target(t, "ft-"+x, "oracle-prod", jurisdiction, "dc/corp-prod")
	c.AcceptJurisdictionChanges = true
	c.Config.Charter.Accounts = &charter.Accounts{Jurisdiction: "dc/corp-prod/{account}", SourceJurisdiction: "dc/corp-prod/{account}/app/{project}", TargetJurisdiction: "dc/corp-prod/{account}/data/{tenancy}"}
	err = c.jurisdictions(ctx)
	if err == nil || !strings.Contains(err.Error(), "source fs-"+x+": jurisdiction "+jurisdiction+" does not conform") ||
		!strings.Contains(err.Error(), "target ft-"+x+": jurisdiction "+jurisdiction+" does not conform") {
		t.Errorf("got %v", err)
	}
}

// TN-16, and a platform whose plugin cannot hold a namespace.
func TestNamespaces(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	x := v.x
	account := "st" + x
	c := v.checks(t)
	c.Config.Charter.Accounts = &charter.Accounts{Jurisdiction: "dc/corp-prod/{account}", SourceJurisdiction: "dc/corp-prod/{account}", TargetJurisdiction: "dc/corp-prod/{account}"}
	declared := func(string) string { return "schema" }
	id := v.target(t, "nt-"+x, "oracle-prod", "dc/corp-prod/"+account, "dc/corp-prod")
	v.exec(t, `update targets set definition = '{"schema":"other"}' where id = $1`, id)
	if err := c.Namespaces(ctx, declared); err != nil {
		t.Errorf("no template: %v", err)
	}
	// templates with no namespace_template: an operator picks the schema, and
	// so any tenant's role
	prod, _ := c.Instances.Current().Platform("oracle-prod")
	bounds := prod.Config
	setPlatform(c, "oracle-prod", func(p *instances.Definition) {
		p.Config = json.RawMessage(`{"grantable_role_templates":["{namespace}_read"]}`)
	})
	var unbound bytes.Buffer
	logger := c.Logger
	c.Logger = slog.New(slog.NewTextHandler(&unbound, nil))
	if err := c.Namespaces(ctx, declared); err != nil {
		t.Errorf("templates alone: %v", err)
	}
	if !strings.Contains(unbound.String(), "no namespace_template") || !strings.Contains(unbound.String(), "oracle-prod") {
		t.Errorf("no warning of unbound templates: %s", unbound.String())
	}
	c.Logger = logger
	setPlatform(c, "oracle-prod", func(p *instances.Definition) { p.Config, p.NamespaceTemplate = bounds, "{account}_ok" })
	if err := c.Namespaces(ctx, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "oracle-prod") || !strings.Contains(err.Error(), "namespace_field") {
		t.Errorf("no capability: %v", err)
	}
	if err := c.Namespaces(ctx, declared); err == nil || !strings.Contains(err.Error(), "nt-"+x) || !strings.Contains(err.Error(), account+"_ok") {
		t.Errorf("TN-16: %v", err)
	}
	v.exec(t, `update targets set definition = jsonb_build_object('schema', $2::text) where id = $1`, id, account+"_ok")
	var logged bytes.Buffer
	c.Logger = slog.New(slog.NewTextHandler(&logged, nil))
	if err := c.Namespaces(ctx, declared); err != nil {
		t.Errorf("matching: %v", err)
	}
	if !strings.Contains(logged.String(), "shared across tenants") || !strings.Contains(logged.String(), "oracle-prod") {
		t.Errorf("no warning of shared roles: %s", logged.String())
	}
}
