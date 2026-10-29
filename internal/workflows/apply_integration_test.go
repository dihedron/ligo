//go:build integration

package workflows

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/outputvalidation"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// insecure: CI's container has no TLS; the lab's DSNs use verify-full.
var insecure = os.Getenv("CI") != ""

// fake plugins: an identity provider of one mode, a platform and a store
// that record what they receive.
type fake struct {
	db   *pgxpool.Pool
	mode pluginv1.IdentityMode

	mu         sync.Mutex
	secret     string // the static secret the identity or the target emits
	targets    int
	rotations  []bool
	stored     *pluginv1.SecretProvisioningPayload
	notStarted []string // INV-05 violations
	targetHook func(*pluginv1.EnsureTargetRequest)
	storeBlock chan struct{} // the first EnsureSecretStore waits on it
	targetSpec string
	validator  *outputvalidation.Validator
}

func (f *fake) started(ctx context.Context, b *pluginv1.BindingContext, stage string) {
	var status, wf string
	err := f.db.QueryRow(ctx, "SELECT status, workflow_id FROM binding_stage_state WHERE binding_id = $1 AND stage = $2", b.GetBindingId(), stage).Scan(&status, &wf)
	if err != nil || status != "STARTED" || !strings.HasSuffix(wf, fmt.Sprintf(":r%d:a%d", b.GetRevision(), b.GetAttempt())) {
		f.mu.Lock()
		f.notStarted = append(f.notStarted, stage)
		f.mu.Unlock()
	}
}

func (f *fake) Health(context.Context, pluginv1.PluginKind, string) error { return nil }

func (f *fake) EnsureIdentity(ctx context.Context, r *pluginv1.EnsureIdentityRequest) (*pluginv1.EnsureIdentityResponse, error) {
	f.started(ctx, r.GetBinding(), "IDENTITY")
	a := &pluginv1.IdentityArtifact{Mode: f.mode, PrincipalId: r.GetBinding().GetDerivedPrincipalName()}
	if f.mode == pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR {
		a.StaticSecret = &pluginv1.StaticSecret{Username: a.PrincipalId, Password: f.secret}
	}
	return &pluginv1.EnsureIdentityResponse{Artifact: a}, nil
}

func (f *fake) EnsureTarget(ctx context.Context, r *pluginv1.EnsureTargetRequest) (*pluginv1.EnsureTargetResponse, error) {
	f.started(ctx, r.GetBinding(), "TARGET")
	f.mu.Lock()
	f.targets++
	f.rotations = append(f.rotations, r.GetBinding().GetRotateStaticSecrets())
	hook := f.targetHook
	f.mu.Unlock()
	if hook != nil {
		hook(r)
	}
	p := &pluginv1.SecretProvisioningPayload{Mode: r.GetIdentity().GetMode()}
	switch r.GetIdentity().GetMode() {
	case pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL:
		p.Payload = &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: &pluginv1.StaticSecret{Username: "u", Password: f.secret}}
	case pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC:
		p.Payload = &pluginv1.SecretProvisioningPayload_DelegatedRole{DelegatedRole: &pluginv1.DelegatedRoleSpec{RoleType: "database-dynamic", CreationStatements: []string{"CREATE ROLE"}}}
	}
	spec := f.targetSpec
	if spec == "" {
		spec = `{"endpoint":"db.internal:5432"}`
	}
	return &pluginv1.EnsureTargetResponse{FinalizedClientSpecJson: []byte(spec), SecretPayload: p}, nil
}

func (f *fake) EnsureSecretStore(ctx context.Context, r *pluginv1.EnsureSecretStoreRequest) (*pluginv1.EnsureSecretStoreResponse, error) {
	f.started(ctx, r.GetBinding(), "SECRET_STORE")
	f.mu.Lock()
	block := f.storeBlock
	f.storeBlock = nil
	f.mu.Unlock()
	if block != nil {
		<-block // a crash: this call never returns
	}
	f.mu.Lock()
	f.stored = r.GetSecretPayload()
	f.mu.Unlock()
	return &pluginv1.EnsureSecretStoreResponse{FinalizedClientAuthJson: []byte(`{"secretPath":"kv/data/bindings/x"}`)}, nil
}

func (f *fake) OutputValidator(pluginv1.PluginKind, string) *outputvalidation.Validator {
	return f.validator
}

// flakyKEK is a local key whose unwrapping can be switched off, as Transit
// unavailable (AC-09).
type flakyKEK struct {
	sealing.KEK
	mu   sync.Mutex
	down bool
}

func (k *flakyKEK) Unwrap(ctx context.Context, w string) ([]byte, error) {
	k.mu.Lock()
	down := k.down
	k.mu.Unlock()
	if down {
		return nil, fmt.Errorf("transit unavailable")
	}
	return k.KEK.Unwrap(ctx, w)
}

type env struct {
	version string
	engine  *Engine
	owner   *pgxpool.Pool
	fake    *fake
	kek     *flakyKEK
}

func validator(t *testing.T, schema string) *outputvalidation.Validator {
	t.Helper()
	al, err := flows.ParseAllowlist([]string{"db.internal:5432"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := outputvalidation.New(schema, al)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func setup(t *testing.T, mode pluginv1.IdentityMode) *env {
	t.Helper()
	key := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	return setupWith(t, mode, "test-"+uuid.NewV7().String(), key, "Canary"+strings.ReplaceAll(uuid.NewV7().String(), "-", ""))
}

// setupWith migrates the database and launches an engine with fake plugins,
// the local key in keyFile, the DBOS application version and the secret
// the fakes emit.
func setupWith(t *testing.T, mode pluginv1.IdentityMode, version, keyFile, secret string) *env {
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
	local, err := sealing.NewLocalKEK(keyFile, true)
	if err != nil {
		t.Fatal(err)
	}
	kek := &flakyKEK{KEK: local}
	f := &fake{db: owner, mode: mode, secret: secret,
		validator: validator(t, `{"type":"object","properties":{"endpoint":{"type":"string","x-ligo-endpoint":true}}}`)}
	e := &Engine{DB: pools.App, Plugins: f, Sealer: sealing.NewSealer(kek), Backoff: Backoff{Attempts: 2, Initial: time.Millisecond, Max: time.Millisecond}}
	v := &env{engine: e, owner: owner, fake: f, kek: kek, version: version}
	launch(t, e, v.version)
	return v
}

// launch gives e a DBOS context of its own, on DBOS's DSN and role, with
// the application version version: each setup has its own, so recovery
// picks up only that test's pending workflows (EXT-09).
func launch(t *testing.T, e *Engine, version string) {
	t.Helper()
	d, err := dbos.NewContext(context.Background(), dbos.Config{AppName: "ligo-workflows-test", DatabaseURL: dsn(t, "DBOS"),
		DatabaseSchema: "dbos", ApplicationVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	e.DBOS = d
	e.Register()
	if err := dbos.Launch(d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dbos.Shutdown(d, 5*time.Second) })
}

// binding commits a source, a target and a PROVISIONING binding at
// revision 1, attempt 1, removed at the end of the test.
func (v *env) binding(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	source, target, id := uuid.NewV7(), uuid.NewV7(), uuid.NewV7()
	x := id.String()[24:]
	regex := `^spiffe://prod\.internal/ns/w/sa/` + x + `$`
	err := pgx.BeginFunc(ctx, v.owner, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by) values ($1, $2, 'dc/corp-prod', 'prod.internal', $3, 't', 't')`, []any{source, "s-" + x, regex}},
			{`insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, created_by, updated_by)
				values ($1, $2, 'pg', 'postgres.v1', 'prod', 'dc/corp-prod', 'dc/corp-prod', '{}', 't', 't')`, []any{target, "t-" + x}},
			{`insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{}', '[]')`, []any{target}},
			{`insert into bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
				identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
				source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision,
				source_trust_domain, source_svid_regex, requested_spec, created_by, updated_by)
				values ($1, $2, $3, $4, 'read', 'prod', 'postgres.v1', 'pg', 'fake.v1', 'id-prod', 'vault.v1', 'vault-prod', 'vault-static',
				'bnd_' || left(md5($1::uuid::text), 16), 'dc/corp-prod', 'dc/corp-prod', 'dc/corp-prod', $5, 1, 1, 'prod.internal', $6, '{"roles":[]}', 't', 't')`,
				[]any{id, "b-" + x, source, target, "ligo:apply:" + id.String() + ":r1:a1", regex}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = v.owner.Exec(ctx, "delete from bindings where id = $1", id)
		_, _ = v.owner.Exec(ctx, "delete from target_access_levels where target_id = $1", target)
		_, _ = v.owner.Exec(ctx, "delete from targets where id = $1", target)
		_, _ = v.owner.Exec(ctx, "delete from sources where id = $1", source)
	})
	return id
}

type row struct {
	phase, step, message string
	activeRevision       *int64
	auth, spec           string
	rotated              bool
}

func (v *env) row(t *testing.T, id uuid.UUID) row {
	t.Helper()
	var r row
	err := v.owner.QueryRow(context.Background(), `select phase, current_step, status_message, active_revision,
		coalesce(active_auth_config::text, ''), coalesce(active_spec::text, ''), last_rotated_at is not null from bindings where id = $1`, id).
		Scan(&r.phase, &r.step, &r.message, &r.activeRevision, &r.auth, &r.spec, &r.rotated)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func wait(t *testing.T, h dbos.WorkflowHandle[string]) (string, error) {
	t.Helper()
	return h.GetResult(dbos.WithHandleTimeout(30 * time.Second))
}

// TestApply: each identity mode reaches ACTIVE with the payload §5.6 routes
// to the store; a stage row is STARTED before its Ensure* (INV-05); the
// active snapshot is set at once (INV-02).
func TestApply(t *testing.T) {
	for _, mode := range []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR,
		pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC, pluginv1.IdentityMode_IDENTITY_MODE_SVID} {
		t.Run(mode.String(), func(t *testing.T) {
			v := setup(t, mode)
			id := v.binding(t)
			h, err := v.engine.Start(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := wait(t, h); err != nil || out != "ACTIVE" {
				t.Fatalf("workflow: %q, %v", out, err)
			}
			r := v.row(t, id)
			if r.phase != "ACTIVE" || r.step != "COMPLETED" || r.activeRevision == nil || *r.activeRevision != 1 ||
				!strings.Contains(r.auth, `"secretStorageStrategy": "vault-static"`) || !strings.Contains(r.auth, `"secretPath"`) || !strings.Contains(r.spec, "db.internal") {
				t.Errorf("binding %+v", r)
			}
			static := mode == pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL || mode == pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR
			if r.rotated != static {
				t.Errorf("last_rotated_at set: %t", r.rotated)
			}
			p := v.fake.stored
			switch {
			case static && p.GetStaticSecret().GetPassword() != v.fake.secret:
				t.Errorf("store payload %v", p)
			case mode == pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC && p.GetDelegatedRole().GetRoleType() != "database-dynamic":
				t.Errorf("store payload %v", p)
			case mode == pluginv1.IdentityMode_IDENTITY_MODE_SVID && p.GetPayload() != nil:
				t.Errorf("store payload %v", p)
			}
			if len(v.fake.notStarted) > 0 {
				t.Errorf("INV-05: no STARTED row before %v", v.fake.notStarted)
			}
			var ensured int
			if err := v.owner.QueryRow(context.Background(), "select count(*) from binding_stage_state where binding_id = $1 and status = 'ENSURED'", id).Scan(&ensured); err != nil || ensured != 3 {
				t.Errorf("%d stages ENSURED (%v)", ensured, err)
			}
			// EXT-02: starting it again returns the same workflow, which does not run again
			h2, err := v.engine.Start(context.Background(), id)
			if err == nil {
				_, _ = wait(t, h2)
			}
			if v.fake.targets != 1 {
				t.Errorf("EnsureTarget called %d times", v.fake.targets)
			}
			canary(t, v, id)
		})
	}
}

// canary checks that the secret appears in no table, of ligo or of DBOS
// (AC-08, ADR-07).
func canary(t *testing.T, v *env, id uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	for pool, schema := range map[string]string{"MIGRATOR": "public", "DBOS": "dbos"} {
		conn, err := pgx.Connect(ctx, dsn(t, pool))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := conn.Query(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'", schema)
		if err != nil {
			t.Fatal(err)
		}
		tables, _ := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, table := range tables {
			var n int
			q := fmt.Sprintf("SELECT count(*) FROM %s t WHERE t::text LIKE '%%' || $1 || '%%'", pgx.Identifier{schema, table}.Sanitize())
			if err := conn.QueryRow(ctx, q, v.fake.secret).Scan(&n); err != nil {
				t.Errorf("%s.%s: %v", schema, table, err)
			} else if n > 0 {
				t.Errorf("the secret is in plaintext in %s.%s", schema, table)
			}
		}
		_ = conn.Close(ctx)
	}
	_ = id
}

// TestOutputRefused: an output outside the allowlist fails the attempt;
// nothing is served (§5.7, INV-13).
func TestOutputRefused(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	v.fake.targetSpec = `{"endpoint":"evil.example:5432"}`
	id := v.binding(t)
	h, err := v.engine.Start(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := wait(t, h); out != "FAILED" || err == nil {
		t.Fatalf("workflow: %q, %v", out, err)
	}
	r := v.row(t, id)
	if r.phase != "FAILED" || r.step != "ensureTarget" || !strings.HasPrefix(r.message, "OUTPUT_VALIDATION_FAILED") || r.activeRevision != nil {
		t.Errorf("binding %+v", r)
	}
	var failures int
	if err := v.owner.QueryRow(context.Background(), "select count(*) from audit_log where resource_id = $1 and action = 'PROVISION_FAILURE'", id).Scan(&failures); err != nil || failures != 1 {
		t.Errorf("PROVISION_FAILURE %d (%v)", failures, err)
	}
}

// TestFenced: a superseded workflow stops at its next fenced write, without
// marking the binding (§6.1 rule 7, ADR-08).
func TestFenced(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	id := v.binding(t)
	v.fake.targetHook = func(*pluginv1.EnsureTargetRequest) {
		_, _ = v.owner.Exec(context.Background(), "update bindings set workflow_id = 'ligo:apply:'||id||':r1:a9' where id = $1", id)
	}
	h, err := v.engine.Start(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wait(t, h); err == nil {
		t.Fatal("the superseded workflow succeeded")
	}
	if r := v.row(t, id); r.phase != "PROVISIONING" || r.activeRevision != nil {
		t.Errorf("binding %+v", r)
	}
}

// TestAC09: when the secret cannot be unsealed at S8 the attempt fails with
// SEALED_SECRET_UNAVAILABLE; a retry is a new attempt that rotates.
func TestAC09(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	id := v.binding(t)
	v.kek.down = true
	h, err := v.engine.Start(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := wait(t, h); out != "FAILED" {
		t.Fatalf("workflow: %q", out)
	}
	if r := v.row(t, id); r.phase != "FAILED" || !strings.HasPrefix(r.message, "SEALED_SECRET_UNAVAILABLE") {
		t.Fatalf("binding %+v", r)
	}
	v.kek.down = false
	if _, err := v.owner.Exec(context.Background(), "update bindings set rotate_static_secrets = false where id = $1", id); err != nil {
		t.Fatal(err)
	}
	h, err = v.engine.Retry(context.Background(), id, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := wait(t, h); out != "ACTIVE" || err != nil {
		t.Fatalf("retry: %q, %v", out, err)
	}
	var wf string
	if err := v.owner.QueryRow(context.Background(), "select workflow_id from bindings where id = $1", id).Scan(&wf); err != nil || !strings.HasSuffix(wf, ":r1:a2") {
		t.Errorf("workflow %s (%v)", wf, err)
	}
	if len(v.fake.rotations) != 2 || !v.fake.rotations[1] {
		t.Errorf("rotation per attempt %v", v.fake.rotations)
	}
}

// TestAC08: ligo is killed after S5; the next process recovers the
// workflow, unseals the secret the killed one sealed, and the binding is
// ACTIVE; S5 is not run again, and no plaintext secret is anywhere. The
// killed ligo is a child process of this test, killed with SIGKILL.
func TestAC08(t *testing.T) {
	if id := os.Getenv("LIGO_AC08_BINDING"); id != "" {
		ac08Child(t, id)
		return
	}
	kekFile := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(kekFile, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	version, canaryValue := "test-"+uuid.NewV7().String(), "Canary"+strings.ReplaceAll(uuid.NewV7().String(), "-", "")
	v := setupWith(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, "parent-"+version, kekFile, canaryValue) // for the fixtures
	id := v.binding(t)
	child := exec.Command(os.Args[0], "-test.run", "^TestAC08$", "-test.count=1")
	child.Env = append(os.Environ(),
		"LIGO_AC08_BINDING="+id.String(),
		"LIGO_AC08_VERSION="+version,
		"LIGO_AC08_KEKFILE="+kekFile,
		"LIGO_AC08_CANARY="+canaryValue)
	child.Stdout, child.Stderr = os.Stderr, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for v.row(t, id).step != "ensureSecretStore" {
		if time.Now().After(deadline) {
			_ = child.Process.Kill()
			t.Fatal("the child did not reach S8")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = child.Process.Kill() // SIGKILL: no cleanup, as a crash
	_ = child.Wait()

	restarted := &Engine{DB: v.engine.DB, Plugins: v.fake, Sealer: v.engine.Sealer, Backoff: v.engine.Backoff}
	launch(t, restarted, version) // recovers the killed process's workflow
	for v.row(t, id).phase != "ACTIVE" {
		if time.Now().After(deadline.Add(30 * time.Second)) {
			t.Fatalf("not recovered: %+v", v.row(t, id))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if v.fake.targets != 0 || v.fake.stored.GetStaticSecret().GetPassword() != canaryValue {
		t.Errorf("EnsureTarget ran again %d times; stored %v", v.fake.targets, v.fake.stored)
	}
	canary(t, v, id)
}

// ac08Child is the ligo that dies: it starts the binding's workflow and
// blocks in S8 until the parent kills it.
func ac08Child(t *testing.T, binding string) {
	v := setupWith(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, os.Getenv("LIGO_AC08_VERSION"), os.Getenv("LIGO_AC08_KEKFILE"), os.Getenv("LIGO_AC08_CANARY"))
	v.fake.storeBlock = make(chan struct{})
	id, err := uuid.Parse(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.engine.Start(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	select {} // until killed
}
