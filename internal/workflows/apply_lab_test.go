//go:build integration && lab

package workflows

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func labEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: run the lab tests with test/lab/lab.sh test --on ligo1", name)
	}
	return v
}

func labRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(labEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	return roots
}

func labClient(t *testing.T) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: labRoots(t), MinVersion: tls.VersionTLS12}}}
}

// labPlugins starts the plugin manager with the lab's three plugins in the
// zone prod: target-local.v1, target-postgres (platform pg-ledger, wired to
// them) and store-vault.
func labPlugins(t *testing.T) *pluginmgr.Manager {
	t.Helper()
	zone := config.Zone{Name: "prod", TrustDomain: "prod.lab", SPIFFEWorkloadSocket: labEnv(t, "LIGO_TEST_SPIRE_PROD_SOCKET")}
	aud := labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE")
	sum := func(name string) []byte {
		b, err := hex.DecodeString(labEnv(t, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	selector := func(binary string) *pluginv1.SVIDSelectorConfig {
		return &pluginv1.SVIDSelectorConfig{MatchExpr: `path == "/ligo/plugin/` + binary + `"`, JwtAudience: []string{aud}}
	}
	target := `{"host":"pg.ligo.lab","port":5432,"database":"ledger","grantable_roles":["LEDGER_RO_ROLE","LEDGER_RW_ROLE"],"ca_file":"` +
		labEnv(t, "LIGO_TEST_CA") + `","allowed_endpoints":["pg.ligo.lab:5432"],"bootstrap_credential":{"source":"vault","address":"` +
		labEnv(t, "LIGO_TEST_BAO_PROD_ADDR") + `","auth_mount":"jwt-spiffe","role":"ligo-plugin-target-postgres","jwt_audience":"` + aud +
		`","kv_path":"kv/data/ligo/bootstrap/target-postgres"}}`
	vault := `{"address":"` + labEnv(t, "LIGO_TEST_BAO_PROD_ADDR") + `","auth_mount":"jwt-spiffe","role":"ligo-plugin-store-vault","db_connection":"lab-pg","ca_file":"` +
		labEnv(t, "LIGO_TEST_CA") + `","allowed_endpoints":["bao-prod.ligo.lab:8200"]}`
	m := pluginmgr.New([]pluginmgr.Spec{
		{Type: "target-local.v1", Kind: pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, Builtin: true, Zone: zone,
			Instances: []*pluginv1.InstanceDescriptor{{Name: "local-prod", ConfigJson: "{}"}}},
		{Type: "postgres.v1", Kind: pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, Binary: "target-postgres", SHA256: sum("LIGO_TEST_TARGET_POSTGRES_SHA256"), Zone: zone,
			Instances: []*pluginv1.InstanceDescriptor{{Name: "pg-ledger", ConfigJson: target, SvidSelector: selector("target-postgres"),
				IdentityProviderType: "target-local.v1", IdentityProviderInstance: "local-prod",
				SecretStoreType: "vault.v1", SecretStoreInstance: "vault-prod", SecretStorageStrategy: "vault-static"}}},
		{Type: "vault.v1", Kind: pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, Binary: "store-vault", SHA256: sum("LIGO_TEST_STORE_VAULT_SHA256"), Zone: zone,
			Instances: []*pluginv1.InstanceDescriptor{{Name: "vault-prod", ConfigJson: vault, SvidSelector: selector("store-vault")}}},
	}, pluginmgr.Options{Directory: labEnv(t, "LIGO_TEST_PLUGIN_DIR"), Owner: pluginmgr.Root, RPCTimeout: 30 * time.Second,
		MaxConcurrentRPCsPerInstance: 4, Backoff: config.Backoff{Initial: time.Second, Max: 10 * time.Second}, Logger: slog.Default()})
	t.Cleanup(m.Stop)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestLabApply: a binding filed through the bindings service is applied at
// once (a self-service scope), its workflow starts after the commit and
// provisions the three stages with the lab's plugins, sealing with Transit;
// the stored secret opens the ledger database (§6.2.2, §6.4, AC-01).
func TestLabApply(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, labEnv(t, "LIGO_TEST_PG_MIGRATOR_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	pools, err := store.Open(ctx, labEnv(t, "LIGO_TEST_PG_APP_DSN"), labEnv(t, "LIGO_TEST_PG_READER_DSN"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, labEnv(t, "LIGO_TEST_PG_MIGRATOR_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)

	m := labPlugins(t)
	kek, err := sealing.NewTransitKEK(sealing.TransitConfig{Address: labEnv(t, "LIGO_TEST_BAO_PROD_ADDR"), AuthMount: "jwt-spiffe", Role: "ligo-sealer",
		JWTAudience: labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE"), Mount: "transit", KeyName: "ligo-interstage"},
		sealing.WorkloadJWT{Addr: labEnv(t, "LIGO_TEST_SPIRE_PROD_SOCKET")}, labClient(t))
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{DB: pools.App, Plugins: Manager(m), Sealer: sealing.NewSealer(kek)}
	d, err := dbos.NewContext(ctx, dbos.Config{AppName: "ligo-lab", DatabaseURL: labEnv(t, "LIGO_TEST_PG_DBOS_DSN"), DatabaseSchema: "dbos",
		ApplicationVersion: "lab-" + uuid.NewV7().String()})
	if err != nil {
		t.Fatal(err)
	}
	engine.DBOS = d
	engine.Register()
	if err := dbos.Launch(d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dbos.Shutdown(d, 5*time.Second) })

	x := uuid.NewV7().String()[24:]
	source, target := "e2e-src-"+x, "e2e-ledger-"+x
	targetID := uuid.NewV7()
	err = pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by) values ($1, $2, 'dc/corp-prod', 'prod.lab', $3, 't', 't')`,
				[]any{uuid.NewV7(), source, `^spiffe://prod\.lab/ns/e2e/sa/` + x + `$`}},
			{`insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, created_by, updated_by)
				values ($1, $2, 'pg-ledger', 'postgres.v1', 'prod', 'dc/corp-prod', 'dc/corp-prod', '{"database":"ledger","schema":"ledger"}', 't', 't')`, []any{targetID, target}},
			{`insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{"roles":["LEDGER_RO_ROLE"]}', '["role:LEDGER_RO_ROLE"]')`, []any{targetID}},
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

	bs := &bindings.Service{DB: pools.App, Validate: bindings.Plugins(m),
		Rules: &bindings.Rules{Regex: regexpolicy.DefaultPolicy(), MaxExpiry: 24 * time.Hour, Platforms: map[string]bindings.Platform{"pg-ledger": {
			Name: "pg-ledger", Type: "postgres.v1", Zone: "prod", Scope: "dc/corp-prod", AllowedTrustDomains: []string{"prod.lab"},
			IdentityProviderType: "target-local.v1", IdentityProviderInstance: "local-prod", SecretStoreType: "vault.v1", SecretStoreInstance: "vault-prod",
			SecretStorageStrategy: "vault-static"}}},
		Start: func(ctx context.Context, id uuid.UUID) error { _, err := engine.Start(ctx, id); return err }}
	bs.Requests = &changerequests.Service{DB: pools.App, Policy: &governance.Policy{RequireDistinctApprovers: true}, TTL: time.Hour,
		Resources: map[string]changerequests.Resource{"BINDING": bs}}
	operator := changerequests.Caller{Principal: authz.Principal{Name: "olga"}, Grants: authz.Grants{{Role: config.RoleOperator, Scopes: []string{"dc/*"}}}}
	name := "e2e-" + x
	r, err := bs.Create(ctx, operator, []byte(fmt.Sprintf(`{"name":%q,"source":%q,"target":%q,"accessLevel":"read"}`, name, source, target)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "APPLIED" {
		t.Fatalf("request %s", r.Status)
	}
	id := *r.ResourceID
	t.Cleanup(func() {
		ctx := context.Background()
		// no delete workflow yet (§6.5): undo the stages by hand, store first
		var b struct{ id, principal string }
		_ = owner.QueryRow(ctx, "select id::text, derived_principal_name from bindings where id = $1", id).Scan(&b.id, &b.principal)
		bc := &pluginv1.BindingContext{BindingId: b.id, DerivedPrincipalName: b.principal}
		_ = m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, "vault-prod", true, func(ctx context.Context, c *pluginmgr.Client) error {
			_, err := c.Store.CleanupSecretStore(ctx, &pluginv1.CleanupSecretStoreRequest{Instance: "vault-prod", Binding: bc, SecretStorageStrategy: "vault-static"})
			return err
		})
		_ = m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, "pg-ledger", true, func(ctx context.Context, c *pluginmgr.Client) error {
			_, err := c.Platform.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg-ledger", Binding: bc})
			return err
		})
		_, _ = owner.Exec(ctx, "delete from change_requests where resource_name = $1", name)
		_, _ = owner.Exec(ctx, "delete from bindings where id = $1", id)
		_, _ = owner.Exec(ctx, "delete from target_access_levels where target_id = $1", targetID)
		_, _ = owner.Exec(ctx, "delete from targets where id = $1", targetID)
		_, _ = owner.Exec(ctx, "delete from sources where name = $1", source)
	})

	deadline := time.Now().Add(90 * time.Second)
	var phase, message string
	var auth []byte
	for {
		if err := owner.QueryRow(ctx, "select phase, status_message, coalesce(active_auth_config::text, '') from bindings where id = $1", id).Scan(&phase, &message, &auth); err != nil {
			t.Fatal(err)
		}
		if phase != "PROVISIONING" || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if phase != "ACTIVE" {
		t.Fatalf("binding %s: %s", phase, message)
	}
	var a struct {
		Strategy string `json:"secretStorageStrategy"`
		Config   struct {
			SecretPath string `json:"secretPath"`
		} `json:"config"`
	}
	if err := json.Unmarshal(auth, &a); err != nil || a.Strategy != "vault-static" || a.Config.SecretPath != "kv/data/bindings/"+id.String() {
		t.Fatalf("auth %s (%v)", auth, err)
	}
	secret := checkRead(t, a.Config.SecretPath)
	db, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@pg.ligo.lab:5432/ledger?sslmode=verify-full&sslrootcert=%s",
		secret["username"], secret["password"], labEnv(t, "LIGO_TEST_CA")))
	if err != nil {
		t.Fatalf("the stored credential does not connect: %v", err)
	}
	defer func() { _ = db.Close(ctx) }()
	if _, err := db.Exec(ctx, "SELECT count(*) FROM ledger.entries"); err != nil {
		t.Errorf("read with the stored credential: %v", err)
	}
}

// checkRead reads a KV v2 secret as the lab-only role lab-standins-check.
func checkRead(t *testing.T, path string) map[string]string {
	t.Helper()
	ctx := context.Background()
	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE")}, workloadapi.WithAddr(labEnv(t, "LIGO_TEST_SPIRE_PROD_SOCKET")))
	if err != nil {
		t.Fatal(err)
	}
	client := labClient(t)
	call := func(method, path, token string, body []byte, out any) {
		req, _ := http.NewRequestWithContext(ctx, method, labEnv(t, "LIGO_TEST_BAO_PROD_ADDR")+"/v1/"+path, bytes.NewReader(body))
		if token != "" {
			req.Header.Set("X-Vault-Token", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
		}
		_ = json.Unmarshal(data, out)
	}
	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	body, _ := json.Marshal(map[string]string{"role": "lab-standins-check", "jwt": svid.Marshal()})
	call(http.MethodPost, "auth/jwt-spiffe/login", "", body, &login)
	var secret struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	call(http.MethodGet, path, login.Auth.ClientToken, nil, &secret)
	return secret.Data.Data
}
