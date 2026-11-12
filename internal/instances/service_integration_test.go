//go:build integration

package instances

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/metrics"
	"github.com/dihedron/ligo/internal/sealing"
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

func caller(name, role string, jurisdictions ...string) changerequests.Caller {
	return changerequests.Caller{Principal: authz.Principal{Name: name}, Grants: authz.Grants{{Role: role, Jurisdictions: jurisdictions}}}
}

var (
	alice = caller("alice", config.RoleOperator, "dc/*")
	bob   = caller("bob", config.RoleApprover, "dc/*")
	// both roles: still never decides its own request
	carol = changerequests.Caller{Principal: authz.Principal{Name: "carol"}, Grants: authz.Grants{
		{Role: config.RoleOperator, Jurisdictions: []string{"dc/*"}}, {Role: config.RoleApprover, Jurisdictions: []string{"dc/*"}}}}
)

// fakePlugins answers for every type: each instance resolves its own SVID,
// unless its matchExpr is hint == "shared", and reports its config's
// allowed_endpoints.
type fakePlugins struct{ resolved map[string]string }

func (f *fakePlugins) Validate(_ context.Context, _ Kind, d *Definition) (string, []string, error) {
	if d.SVIDSelector == nil {
		return "", nil, nil
	}
	id := "spiffe://prod.internal/plugin/" + d.Metadata.Name
	if d.SVIDSelector.MatchExpr == `hint == "shared"` {
		id = "spiffe://prod.internal/plugin/shared"
	}
	return id, d.AllowedEndpoints(), nil
}

func (f *fakePlugins) Resolved(string, string) map[string]string { return f.resolved }

func (f *fakePlugins) Wire(context.Context, *Definition) error { return nil }

type world struct {
	s        *Service
	registry *Registry
	owner    *pgxpool.Pool
	plugins  *fakePlugins
	defs     []*Definition
}

func setup(t *testing.T) *world {
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
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	path := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	kek, err := sealing.NewLocalKEK(path, true)
	if err != nil {
		t.Fatal(err)
	}
	signer := sealing.NewLocalSigner(kek)
	env, defs := example(t)
	data, _ := os.ReadFile("../../examples/server.yaml")
	cfg, _ := config.Parse(data)
	w := &world{owner: owner, plugins: &fakePlugins{}, defs: defs}
	w.registry = &Registry{DB: pools.App, Signer: signer, Interval: time.Minute, Logger: slog.Default()}
	w.s = &Service{DB: pools.App, Env: env, Instances: w.registry, Signer: signer, Plugins: w.plugins, Logger: slog.Default()}
	w.s.Requests = &changerequests.Service{DB: pools.App, Policy: cfg.Policy(), TTL: time.Hour, Resources: map[string]changerequests.Resource{}}
	for _, k := range Kinds {
		w.s.Requests.Resources[string(k)] = w.s
	}
	return w
}

// unique is d renamed for this test, removed with its requests at the end.
func (w *world) unique(t *testing.T, name string) *Definition {
	t.Helper()
	src := find(w.defs, name)
	suffix := uuid.NewV7().String()[30:]
	d := mutate(t, src, func(m map[string]any) { m["metadata"].(map[string]any)["name"] = name + "-" + suffix })
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = w.owner.Exec(ctx, "delete from change_requests where resource_name = $1", d.Metadata.Name)
		_, _ = w.owner.Exec(ctx, "delete from instances where name = $1", d.Metadata.Name)
	})
	return d
}

func body(t *testing.T, d *Definition, extra map[string]any) []byte {
	t.Helper()
	data, _ := json.Marshal(d)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	for k, v := range extra {
		m[k] = v
	}
	data, _ = json.Marshal(m)
	return data
}

// created files and approves d.
func (w *world) created(t *testing.T, k Kind, d *Definition) {
	t.Helper()
	ctx := context.Background()
	r, err := w.s.Create(ctx, alice, k, body(t, d, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := w.registry.Load(ctx); err != nil {
		t.Fatal(err)
	}
}

func status(err error) string {
	if e := (*changerequests.Error)(nil); errors.As(err, &e) {
		return e.Slug
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// TestLifecycle: create, approve, update and retire a secret store; the
// registry follows; four eyes hold (§5).
func TestLifecycle(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	d := w.unique(t, "vault-prod")
	r, err := w.s.Create(ctx, alice, SecretStore, body(t, d, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sides) != 1 || r.Sides[0].Basis != changerequests.BasisHuman || r.Sides[0].Jurisdiction != "dc/corp-prod" {
		t.Fatalf("sides %+v", r.Sides)
	}
	if _, err := w.s.Requests.Approve(ctx, alice, r.ID, r.PayloadSHA256, "", "mine"); status(err) != "forbidden" && status(err) != "four-eyes-violation" {
		t.Errorf("the requester decided: %v", err)
	}
	if _, err := w.s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := w.registry.Load(ctx); err != nil {
		t.Fatal(err)
	}
	got, ok := w.registry.Current().Get(SecretStore, d.Metadata.Name)
	if !ok || got.Metadata.Jurisdiction != "dc/corp-prod" {
		t.Fatalf("registry: %+v", got)
	}
	// an update: immutable fields refused, a change applied at revision 2
	if _, err := w.s.Update(ctx, alice, SecretStore, d.Metadata.Name, body(t, mutate(t, d, func(m map[string]any) {
		m["metadata"].(map[string]any)["realm"] = "test"
	}), map[string]any{"expectedRevision": 1})); status(err) != "immutable-field" {
		t.Errorf("realm changed: %v", err)
	}
	changed := mutate(t, d, func(m map[string]any) { m["config"].(map[string]any)["role"] = "ligo-plugin-vault-prod-2" })
	r, err = w.s.Update(ctx, alice, SecretStore, d.Metadata.Name, body(t, changed, map[string]any{"expectedRevision": 1}))
	if err != nil {
		t.Fatal(err)
	}
	if diff, err := w.s.Requests.DiffOf(ctx, r); err != nil || len(diff.([]changerequests.Change)) != 1 {
		t.Errorf("diff %v %v", diff, err)
	}
	if _, err := w.s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	var revision int64
	_ = w.owner.QueryRow(ctx, "select revision from instances where name = $1", d.Metadata.Name).Scan(&revision)
	if revision != 2 {
		t.Errorf("revision %d", revision)
	}
	// retire
	if err := w.registry.Load(ctx); err != nil {
		t.Fatal(err)
	}
	r, err = w.s.Retire(ctx, alice, SecretStore, d.Metadata.Name, changerequests.Common{ExpectedRevision: &revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := w.registry.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.registry.Current().Get(SecretStore, d.Metadata.Name); ok {
		t.Error("a retired instance is in force")
	}
	if _, err := w.s.Create(ctx, alice, SecretStore, body(t, d, nil)); status(err) != "invalid-transition" {
		t.Errorf("a retired name was reused: %v", err)
	}
}

// TestAlwaysHuman: an operator who is also an approver, and a jurisdiction
// with no approval required, still get a human side (§5 rule 2).
func TestAlwaysHuman(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	d := w.unique(t, "no-store-prod")
	r, err := w.s.Create(ctx, carol, SecretStore, body(t, d, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || r.Sides[0].Decision != "" {
		t.Fatalf("decided at creation: %+v", r)
	}
	if _, err := w.s.Requests.Approve(ctx, carol, r.ID, r.PayloadSHA256, "", "mine"); err == nil {
		t.Error("the requester decided its own request")
	}
}

// TestWiringAndInUse: a platform needs its instances ACTIVE in its realm,
// and holds them (§6 rules 6 and 9).
func TestWiringAndInUse(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	ldap, vault := w.unique(t, "ldap-prod"), w.unique(t, "vault-prod")
	oracle := w.unique(t, "oracle-prod")
	wire := func(m map[string]any) {
		m["identityProvider"] = map[string]any{"type": "openldap.v1", "instance": ldap.Metadata.Name}
		m["secretStore"] = map[string]any{"type": "vault.v1", "instance": vault.Metadata.Name, "secretStorageStrategy": "vault-static"}
	}
	oracle = mutate(t, oracle, wire)
	if _, err := w.s.Create(ctx, alice, Platform, body(t, oracle, nil)); status(err) != "validation-failed" {
		t.Errorf("wired to nothing: %v", err)
	}
	w.created(t, IdentityProvider, ldap)
	w.created(t, SecretStore, vault)
	w.created(t, Platform, oracle)
	if _, ok := w.registry.Current().Platform(oracle.Metadata.Name); !ok {
		t.Fatal("the platform is not in force")
	}
	one := int64(1)
	if _, err := w.s.Retire(ctx, alice, SecretStore, vault.Metadata.Name, changerequests.Common{ExpectedRevision: &one}); status(err) != "instance-in-use" {
		t.Errorf("retired a store a platform uses: %v", err)
	}
}

// TestSharedSVID: rule 7, one SVID for two instances only when both opt
// in, and share a jurisdiction unless the type lists the SVID in
// instance_bounds.shared_svids (T-22c).
func TestSharedSVID(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	id := "spiffe://prod.internal/plugin/shared"
	sharing := func(d *Definition, optIn bool) *Definition {
		return mutate(t, d, func(m map[string]any) {
			m["svidSelector"] = map[string]any{"matchExpr": `hint == "shared"`, "jwtAudience": d.SVIDSelector.JWTAudience, "allowSharedSvid": optIn}
		})
	}
	first := sharing(w.unique(t, "vault-prod"), true)
	w.created(t, SecretStore, first)
	w.plugins.resolved = map[string]string{first.Metadata.Name: id}
	other := func(jurisdiction string, optIn bool) *Definition {
		return sharing(mutate(t, w.unique(t, "vault-prod"), func(m map[string]any) { m["metadata"].(map[string]any)["jurisdiction"] = jurisdiction }), optIn)
	}
	for name, tc := range map[string]struct {
		d      *Definition
		listed bool
		ok     bool
	}{
		"one jurisdiction, both opt in":  {other("dc/corp-prod", true), false, true},
		"one jurisdiction, no opt-in":    {other("dc/corp-prod", false), false, false},
		"another jurisdiction":           {other("dc/corp-test", true), false, false},
		"another jurisdiction, listed":   {other("dc/corp-test", true), true, true},
		"listed, but the other opts out": {other("dc/corp-test", false), true, false},
	} {
		typ := w.s.Env.Types["vault.v1"]
		typ.SharedSVIDs = map[string]bool{}
		if tc.listed {
			typ.SharedSVIDs[id] = true
		}
		w.s.Env.Types["vault.v1"] = typ
		_, err := w.s.Create(ctx, alice, SecretStore, body(t, tc.d, nil))
		if (err == nil) != tc.ok || err != nil && status(err) != "validation-failed" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestBoundsRefused: an endpoint outside instance_bounds (rule 5).
func TestBoundsRefused(t *testing.T) {
	w := setup(t)
	d := mutate(t, w.unique(t, "vault-prod"), func(m map[string]any) {
		m["config"].(map[string]any)["allowed_endpoints"] = []string{"vault.prod.internal:8200", "evil.example:8200"}
	})
	if _, err := w.s.Create(context.Background(), alice, SecretStore, body(t, d, nil)); status(err) != "validation-failed" {
		t.Errorf("%v", err)
	}
}

// TestDrift: a row changed outside ligo is quarantined and audited once; a
// new request clears it (§8, T-22b).
func TestDrift(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	d := w.unique(t, "vault-prod")
	w.created(t, SecretStore, d)
	edited := `jsonb_set(definition, '{config,address}', '"https://vault.prod.internal:8201"')`
	for _, step := range []struct{ name, sql string }{ // in this order: each leaves a new hash to report
		{"definition only", "update instances set definition = " + edited + " where name = $1"},
		{"definition and its hash", "update instances set definition = " + edited + ", definition_sha256 = repeat('0', 64) where name = $1"},
	} {
		name, sql := step.name, step.sql
		if _, err := w.owner.Exec(ctx, sql, d.Metadata.Name); err != nil {
			t.Fatal(err)
		}
		if err := w.registry.Load(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := w.registry.Current().Get(SecretStore, d.Metadata.Name); ok {
			t.Errorf("%s: a drifted instance is in force", name)
		}
		if metrics.Value(metrics.InstanceDrift.WithLabelValues(string(SecretStore), d.Metadata.Name)) != 1 {
			t.Errorf("%s: no drift metric", name)
		}
	}
	if err := w.registry.Load(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = w.owner.QueryRow(ctx, "select count(*) from audit_log where action = 'SYSTEM_INSTANCE_DRIFT' and resource_name = $1", d.Metadata.Name).Scan(&n)
	if n != 2 { // one per drifted hash, not one per load
		t.Errorf("%d drift entries", n)
	}
	// fix: an update from the audited revision writes and signs it again
	var revision int64
	_ = w.owner.QueryRow(ctx, "select revision from instances where name = $1", d.Metadata.Name).Scan(&revision)
	r, err := w.s.Update(ctx, alice, SecretStore, d.Metadata.Name, body(t, d, map[string]any{"expectedRevision": revision}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := w.registry.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.registry.Current().Get(SecretStore, d.Metadata.Name); !ok {
		t.Error("still quarantined after a new request")
	}
	if metrics.Value(metrics.InstanceDrift.WithLabelValues(string(SecretStore), d.Metadata.Name)) != 0 {
		t.Error("drift metric not cleared")
	}
}

// TestPlatformUpdateGuards: an update may not strand an existing target:
// targetJurisdictions must still cover it, and namespaceTemplate cannot
// change while the platform has targets (§4.3).
func TestPlatformUpdateGuards(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	ldap, vault, oracle := w.unique(t, "ldap-prod"), w.unique(t, "vault-prod"), w.unique(t, "oracle-prod")
	oracle = mutate(t, oracle, func(m map[string]any) {
		m["identityProvider"] = map[string]any{"type": "openldap.v1", "instance": ldap.Metadata.Name}
		m["secretStore"] = map[string]any{"type": "vault.v1", "instance": vault.Metadata.Name, "secretStorageStrategy": "vault-static"}
	})
	w.created(t, IdentityProvider, ldap)
	w.created(t, SecretStore, vault)
	w.created(t, Platform, oracle)
	target := "guard-" + uuid.NewV7().String()[30:]
	if _, err := w.owner.Exec(ctx, `insert into targets (id, name, platform, platform_type, realm, jurisdiction, platform_jurisdiction, definition, created_by, updated_by)
		values ($1, $2, $3, 'oracle.v1', 'prod', 'dc/corp-prod/ledger', 'dc/corp-prod', '{}', 't', 't')`, uuid.NewV7(), target, oracle.Metadata.Name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = w.owner.Exec(context.Background(), "delete from targets where name = $1", target) })
	for name, f := range map[string]func(map[string]any){
		"narrowed":  func(m map[string]any) { m["targetJurisdictions"] = []string{"dc/corp-prod/other"} },
		"namespace": func(m map[string]any) { m["namespaceTemplate"] = "{account}_{tenancy}" },
	} {
		_, err := w.s.Update(ctx, alice, Platform, oracle.Metadata.Name, body(t, mutate(t, oracle, f), map[string]any{"expectedRevision": 1}))
		if status(err) != "validation-failed" && status(err) != "invalid-transition" {
			t.Errorf("%s: %v", name, err)
		}
	}
	widened := mutate(t, oracle, func(m map[string]any) { m["targetJurisdictions"] = []string{"dc/corp-prod/*", "dc/shared/*"} })
	if _, err := w.s.Update(ctx, alice, Platform, oracle.Metadata.Name, body(t, widened, map[string]any{"expectedRevision": 1})); err != nil {
		t.Errorf("widened: %v", err)
	}
}

// TestRefusals: the service's refusals before anything is filed, and Get's
// two views (§5, §10.1).
func TestRefusals(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	d := w.unique(t, "vault-prod")
	w.created(t, SecretStore, d)
	name := d.Metadata.Name
	one, two := int64(1), int64(7)
	viewer := caller("vera", config.RoleViewer, "*")
	for label, tc := range map[string]struct {
		run  func() error
		slug string
	}{
		"create with expectedRevision": {func() error {
			_, err := w.s.Create(ctx, alice, SecretStore, body(t, d, map[string]any{"expectedRevision": 1}))
			return err
		}, "validation-failed"},
		"create of another kind": {func() error { _, err := w.s.Create(ctx, alice, Platform, body(t, d, nil)); return err }, "validation-failed"},
		"create outside the jurisdiction": {func() error {
			_, err := w.s.Create(ctx, caller("olga", config.RoleOperator, "cloud/*"), SecretStore, body(t, w.unique(t, "vault-prod"), nil))
			return err
		}, "forbidden"},
		"update without expectedRevision": {func() error { _, err := w.s.Update(ctx, alice, SecretStore, name, body(t, d, nil)); return err }, "validation-failed"},
		"update renaming": {func() error {
			_, err := w.s.Update(ctx, alice, SecretStore, "other", body(t, d, map[string]any{"expectedRevision": 1}))
			return err
		}, "immutable-field"},
		"update at a stale revision": {func() error {
			_, err := w.s.Update(ctx, alice, SecretStore, name, body(t, d, map[string]any{"expectedRevision": 7}))
			return err
		}, "revision-conflict"},
		"update of an unknown instance": {func() error {
			x := mutate(t, d, func(m map[string]any) { m["metadata"].(map[string]any)["name"] = "nowhere-x" })
			_, err := w.s.Update(ctx, alice, SecretStore, "nowhere-x", body(t, x, map[string]any{"expectedRevision": 1}))
			return err
		}, "not-found"},
		"retire without expectedRevision": {func() error {
			_, err := w.s.Retire(ctx, alice, SecretStore, name, changerequests.Common{})
			return err
		}, "validation-failed"},
		"retire at a stale revision": {func() error {
			_, err := w.s.Retire(ctx, alice, SecretStore, name, changerequests.Common{ExpectedRevision: &two})
			return err
		}, "revision-conflict"},
		"retire by a viewer": {func() error {
			_, err := w.s.Retire(ctx, viewer, SecretStore, name, changerequests.Common{ExpectedRevision: &one})
			return err
		}, "forbidden"},
	} {
		if err := tc.run(); status(err) != tc.slug {
			t.Errorf("%s: %v, want %s", label, err, tc.slug)
		}
	}
	if rev, def, decider, err := w.s.Get(ctx, alice, SecretStore, name); err != nil || rev != 1 || def == nil || !decider {
		t.Errorf("operator: %d %v %v", rev, decider, err)
	}
	if _, _, decider, err := w.s.Get(ctx, viewer, SecretStore, name); err != nil || decider {
		t.Errorf("viewer: %v %v", decider, err)
	}
	// a second pending request on the same instance
	if _, err := w.s.Update(ctx, alice, SecretStore, name, body(t, d, map[string]any{"expectedRevision": 1})); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Update(ctx, alice, SecretStore, name, body(t, d, map[string]any{"expectedRevision": 1})); status(err) != "change-request-pending" {
		t.Errorf("two pending: %v", err)
	}
}

// TestIdentityProviderInUse: an identity provider a platform is wired to
// cannot be retired, at filing and again at approval (§6 rule 9).
func TestIdentityProviderInUse(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	ldap, vault, oracle := w.unique(t, "ldap-prod"), w.unique(t, "vault-prod"), w.unique(t, "oracle-prod")
	w.created(t, IdentityProvider, ldap)
	w.created(t, SecretStore, vault)
	one := int64(1)
	r, err := w.s.Retire(ctx, alice, IdentityProvider, ldap.Metadata.Name, changerequests.Common{ExpectedRevision: &one})
	if err != nil {
		t.Fatal(err)
	}
	// a platform wired to it is applied before the retirement is approved
	w.created(t, Platform, mutate(t, oracle, func(m map[string]any) {
		m["identityProvider"] = map[string]any{"type": "openldap.v1", "instance": ldap.Metadata.Name}
		m["secretStore"] = map[string]any{"type": "vault.v1", "instance": vault.Metadata.Name, "secretStorageStrategy": "vault-static"}
	}))
	if _, err := w.s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err == nil || !strings.Contains(err.Error(), "is wired to") {
		t.Errorf("approved the retirement of a wired identity provider: %v", err)
	}
	if _, err := w.s.Retire(ctx, alice, IdentityProvider, ldap.Metadata.Name, changerequests.Common{ExpectedRevision: &one}); status(err) != "instance-in-use" &&
		status(err) != "change-request-pending" {
		t.Errorf("filing: %v", err)
	}
}

// TestRegistryListens: a registry run in the background learns of an applied
// change by LISTEN, as another replica would, and calls OnChange.
func TestRegistryListens(t *testing.T) {
	w := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := make(chan struct{}, 16)
	other := &Registry{DB: w.registry.DB, Signer: w.registry.Signer, Interval: time.Hour, Logger: slog.Default(),
		OnChange: func(*Set) { changed <- struct{}{} }}
	done := make(chan struct{})
	go func() { other.Run(ctx); close(done) }()
	<-changed // its first load
	d := w.unique(t, "vault-prod")
	w.created(t, SecretStore, d)
	deadline := time.After(10 * time.Second)
	for {
		if _, ok := other.Current().Get(SecretStore, d.Metadata.Name); ok {
			break
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("the other registry did not learn of the change")
		}
	}
	cancel()
	<-done
}
