//go:build integration && lab

package standins

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/jackc/pgx/v5"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// storeVault starts the stand-in with the instance vault-prod.
func storeVault(t *testing.T) *pluginmgr.Client {
	t.Helper()
	cfg := `{"address":"` + labEnv(t, "LIGO_TEST_BAO_PROD_ADDR") + `","auth_mount":"jwt-spiffe","role":"ligo-plugin-store-vault","db_connection":"lab-pg","ca_file":"` +
		labEnv(t, "LIGO_TEST_CA") + `"}`
	return start(t, "store-vault", pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, &pluginv1.InstanceDescriptor{Name: "vault-prod", ConfigJson: cfg})
}

// check reads path on bao-prod as the lab-only role lab-standins-check,
// with ligo's own JWT-SVID; it returns the HTTP status and the data.
func check(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	ctx := context.Background()
	aud := labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE")
	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: aud}, workloadapi.WithAddr(labEnv(t, "LIGO_TEST_SPIRE_PROD_SOCKET")))
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(labEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	do := func(method, path, token string, body []byte) (int, map[string]any) {
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
		var out map[string]any
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out
	}
	body, _ := json.Marshal(map[string]string{"role": "lab-standins-check", "jwt": svid.Marshal()})
	st, login := do(http.MethodPost, "auth/jwt-spiffe/login", "", body)
	if st != http.StatusOK {
		t.Fatalf("lab-standins-check login: %d %v", st, login)
	}
	return do(http.MethodGet, path, login["auth"].(map[string]any)["client_token"].(string), nil)
}

func ensureStore(t *testing.T, c *pluginmgr.Client, b *pluginv1.BindingContext, strategy string, payload *pluginv1.SecretProvisioningPayload) (*pluginv1.EnsureSecretStoreResponse, error) {
	t.Helper()
	return c.Store.EnsureSecretStore(context.Background(), &pluginv1.EnsureSecretStoreRequest{Instance: "vault-prod", Binding: b,
		SecretPayload: payload, SecretStorageStrategy: strategy, Identity: &pluginv1.IdentityArtifact{Mode: payload.GetMode()}})
}

func cleanupStore(c *pluginmgr.Client, b *pluginv1.BindingContext, strategy string) (*pluginv1.CleanupSecretStoreResponse, error) {
	return c.Store.CleanupSecretStore(context.Background(), &pluginv1.CleanupSecretStoreRequest{Instance: "vault-prod", Binding: b, SecretStorageStrategy: strategy})
}

// TestLabStoreVault: with vault-static the stand-in stores the target's
// secret and keeps it when unchanged; a payload that does not fit the
// strategy is refused; cleanup removes it and succeeds again (§5.6, §5.8).
func TestLabStoreVault(t *testing.T) {
	c := storeVault(t)
	b := binding()
	static := &pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL,
		Payload: &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: &pluginv1.StaticSecret{Username: b.GetDerivedPrincipalName(), Password: strings.Repeat("A1", 16)}}}
	t.Cleanup(func() { _, _ = cleanupStore(c, b, "vault-static") })
	r, err := ensureStore(t, c, b, "vault-static", static)
	if err != nil {
		t.Fatal(err)
	}
	var auth struct{ Address, SecretPath, Policy string }
	if err := json.Unmarshal(r.GetFinalizedClientAuthJson(), &auth); err != nil || auth.SecretPath != "kv/data/bindings/"+b.GetBindingId() || auth.Policy != "binding-"+b.GetBindingId() {
		t.Fatalf("client auth %s (%v)", r.GetFinalizedClientAuthJson(), err)
	}
	read := func() string {
		st, out := check(t, auth.SecretPath)
		if st != http.StatusOK {
			return fmt.Sprintf("status %d", st)
		}
		return out["data"].(map[string]any)["data"].(map[string]any)["password"].(string)
	}
	if got := read(); got != strings.Repeat("A1", 16) {
		t.Errorf("stored secret: %s", got)
	}
	unchanged := &pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, SecretUnchanged: true}
	if _, err := ensureStore(t, c, b, "vault-static", unchanged); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != strings.Repeat("A1", 16) {
		t.Errorf("secret after an unchanged ensure: %s", got)
	}
	if _, err := ensureStore(t, c, b, "vault-dynamic", static); code(err) != "INCOMPATIBLE_IDENTITY_MODE" {
		t.Errorf("a static secret with vault-dynamic: %v", err)
	}
	for range 2 {
		if _, err := cleanupStore(c, b, "vault-static"); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := check(t, auth.SecretPath); st != http.StatusNotFound {
		t.Errorf("after cleanup: %d", st)
	}
}

// TestLabStoreVaultDynamic: with vault-dynamic, OpenBao issues credentials
// in the parent role target-postgres created; cleanup revokes them.
func TestLabStoreVaultDynamic(t *testing.T) {
	ctx := context.Background()
	target, store := targetPostgres(t, "vault-dynamic"), storeVault(t)
	b := binding()
	identity := &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC, PrincipalId: b.GetDerivedPrincipalName()}
	t.Cleanup(func() {
		_, _ = cleanupStore(store, b, "vault-dynamic")
		_, _ = target.Platform.CleanupTarget(context.Background(), &pluginv1.CleanupTargetRequest{Instance: "pg-ledger", Binding: b, Identity: identity})
	})
	tr, err := target.Platform.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "pg-ledger", Binding: b, Identity: identity,
		RequestedSpecJson: []byte(`{"database":"ledger","schema":"ledger","roles":["LEDGER_RO_ROLE"],"connectionLimit":0}`)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ensureStore(t, store, b, "vault-dynamic", tr.GetSecretPayload())
	if err != nil {
		t.Fatal(err)
	}
	var auth struct{ Address, CredsPath string }
	if err := json.Unmarshal(r.GetFinalizedClientAuthJson(), &auth); err != nil || auth.CredsPath != "database/creds/binding-"+b.GetBindingId() {
		t.Fatalf("client auth %s (%v)", r.GetFinalizedClientAuthJson(), err)
	}
	st, out := check(t, auth.CredsPath)
	if st != http.StatusOK {
		t.Fatalf("credentials: %d %v", st, out)
	}
	data := out["data"].(map[string]any)
	dsn := fmt.Sprintf("postgres://%s:%s@pg.ligo.lab:5432/ledger?sslmode=verify-full&sslrootcert=%s", data["username"], data["password"], labEnv(t, "LIGO_TEST_CA"))
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("issued credentials do not connect: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT count(*) FROM ledger.entries"); err != nil {
		t.Errorf("read with issued credentials: %v", err)
	}
	_ = conn.Close(ctx)
	if _, err := cleanupStore(store, b, "vault-dynamic"); err != nil {
		t.Fatal(err)
	}
	if conn, err := pgx.Connect(ctx, dsn); err == nil {
		_ = conn.Close(ctx)
		t.Error("revoked credentials still connect")
	}
}
