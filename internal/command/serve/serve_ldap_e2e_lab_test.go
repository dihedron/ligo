//go:build lab

package serve

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/engine"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"
)

// The openldap.v1 e2e, run by lab.sh serve test: a binding on pg-ledger-ldap
// has its account in the directory, and PostgreSQL asks the directory for its
// password (.specs/ligo-openldap-plugin.md, OL-11 to OL-14 and AC-10).

const goneRole = "LEDGER_GONE_ROLE"

// ledgerConn connects to the database ledger as user, verifying the server;
// errors never hold the password.
func ledgerConn(t *testing.T, user, password string) (*pgx.Conn, error) {
	t.Helper()
	cfg, err := pgx.ParseConfig("host=pg.ligo.lab port=5432 dbname=ledger sslmode=verify-full sslrootcert=" + e2eEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = user, password
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return pgx.ConnectConfig(ctx, cfg)
}

// refused checks that the directory, not a password in PostgreSQL, turned
// the credential down.
func refused(t *testing.T, what, user, password string) {
	t.Helper()
	conn, err := ledgerConn(t, user, password)
	if err == nil {
		_ = conn.Close(context.Background())
		t.Errorf("%s connects", what)
	} else if !strings.Contains(err.Error(), "LDAP authentication failed") {
		t.Errorf("%s: %v, want the directory's refusal", what, err)
	}
}

// reads connects with the credential and reads at level read.
func reads(t *testing.T, user, password string) {
	t.Helper()
	conn, err := ledgerConn(t, user, password)
	if err != nil {
		t.Fatalf("the credential does not connect: %v", err)
	}
	ctx := context.Background()
	defer func() { _ = conn.Close(ctx) }()
	var who string
	var n int
	if err := conn.QueryRow(ctx, "SELECT current_user, (SELECT count(*) FROM ledger.entries)").Scan(&who, &n); err != nil || who != user {
		t.Errorf("connected as %q: %v", who, err)
	}
}

// targetAdmin is the lab's target admin, the plugin's own role, for what the
// test needs to see or change on the target.
func targetAdmin(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := ledgerConn(t, "lab_target_admin", e2eEnv(t, "LIGO_TEST_TARGET_ADMIN_PASS"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// roleTag returns whether the role exists and its comment.
func roleTag(t *testing.T, admin *pgx.Conn, role string) (bool, string) {
	t.Helper()
	var comment *string
	err := admin.QueryRow(context.Background(), "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname = $1", role).Scan(&comment)
	if err == pgx.ErrNoRows {
		return false, ""
	}
	if err != nil {
		t.Fatal(err)
	}
	if comment == nil {
		return true, ""
	}
	return true, *comment
}

// account returns whether the principal's account is in the directory and
// its description, read as the plugin's service account.
func account(t *testing.T, principal string) (bool, []string) {
	t.Helper()
	pem, err := os.ReadFile(e2eEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	conn, err := goldap.DialURL(e2eEnv(t, "LIGO_TEST_LDAP_URL"), goldap.DialWithTLSConfig(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	base := e2eEnv(t, "LIGO_TEST_LDAP_BASE")
	if err := conn.Bind("cn=ligo-idp,ou=services,"+base, e2eEnv(t, "LIGO_TEST_LDAP_IDP_PASS")); err != nil {
		t.Fatal(err)
	}
	res, err := conn.Search(goldap.NewSearchRequest("uid="+principal+",ou=ligo-accounts,"+base, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 1, 10, false,
		"(objectClass=*)", []string{"description"}, nil))
	if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
		return false, nil
	}
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("reading the account: %v", err)
	}
	return true, res.Entries[0].GetAttributeValues("description")
}

// ldapSource registers a source for one literal SPIFFE ID.
func ldapSource(t *testing.T, olga, dora *admin, name, workload string) {
	t.Helper()
	id := "spiffe://prod.lab/ns/e2e/sa/" + workload
	code, filed := olga.do("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": name},
		"identity": map[string]any{"trustDomain": "prod.lab", "svidRegex": "^" + strings.ReplaceAll(id, ".", `\.`) + "$",
			"sampleSpiffeIds": []string{id}}, "visibility": map[string]string{"mode": "PRIVATE"}})
	if code != http.StatusAccepted {
		t.Fatalf("source: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
}

// ldapTarget publishes a target on pg-ledger-ldap with one level, read.
func ldapTarget(t *testing.T, olga, dora *admin, name, role string) {
	t.Helper()
	code, filed := olga.do("POST", "/v1/admin/targets", map[string]any{"kind": "Target",
		"metadata":     map[string]string{"name": name, "platform": "pg-ledger-ldap", "scope": "dc/corp-prod/ledger"},
		"definition":   map[string]string{"database": "ledger", "schema": "ledger"},
		"accessLevels": []any{map[string]any{"name": "read", "grants": map[string][]string{"roles": {role}}}},
		"networkFlows": []any{map[string]any{"name": "ledger", "purpose": "DATA", "protocol": "TCP", "destination": "pg.ligo.lab",
			"ports": []int{5432}, "tls": true, "serverName": "pg.ligo.lab"}},
		"visibility": map[string]string{"mode": "PRIVATE"}})
	if code != http.StatusAccepted {
		t.Fatalf("target: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
}

// revoke deletes a binding and waits until its row is gone.
func revoke(t *testing.T, olga, dora *admin, name string, b map[string]any) {
	t.Helper()
	revision := int64(b["metadata"].(map[string]any)["revision"].(float64))
	code, filed := olga.do("DELETE", fmt.Sprintf("/v1/admin/bindings/%s?expectedRevision=%d", name, revision), nil)
	if code != http.StatusAccepted {
		t.Fatalf("revoke: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	phase(t, olga, name, "")
}

// storeRead reads a binding's credential as its workload does: the location
// from ligo's workload API, then the credential with its JWT-SVID. The passwords
// go to a file for lab.sh's search (INV-03, OL-14).
func storeRead(t *testing.T, target, pathKey string, fields func(map[string]string) (string, string)) (user, password string) {
	t.Helper()
	w := newWorkload(t, "workload", false)
	var item map[string]any
	deadline := time.Now().Add(30 * time.Second)
	for item == nil {
		code, _, body := w.get("/v1/bindings?target="+target, "")
		if list := items(body); code == http.StatusOK && len(list) == 1 {
			item = list[0]
		} else if time.Now().After(deadline) {
			t.Fatalf("the workload does not receive the binding: %d %v", code, body)
		} else {
			time.Sleep(500 * time.Millisecond)
		}
	}
	cfg := item["auth"].(map[string]any)["config"].(map[string]any)
	dir := e2eEnv(t, "LIGO_E2E_DIR")
	jwt, err := os.ReadFile(filepath.Join(dir, "workload-store-jwt"))
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(e2eEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	call := func(method, path, token string, body, out any) {
		t.Helper()
		data, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, cfg["address"].(string)+"/v1/"+path, bytes.NewReader(data))
		if token != "" {
			req.Header.Set("X-Vault-Token", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("%s: cannot decode the answer", path)
		}
	}
	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	call(http.MethodPost, "auth/"+cfg["authMount"].(string)+"/login", "", map[string]string{"role": cfg["role"].(string), "jwt": strings.TrimSpace(string(jwt))}, &login)
	var answer struct {
		Data json.RawMessage `json:"data"`
	}
	call(http.MethodGet, cfg[pathKey].(string), login.Auth.ClientToken, nil, &answer)
	var data map[string]string
	if pathKey == "secretPath" { // KV v2 nests it
		var kv struct {
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(answer.Data, &kv); err != nil {
			t.Fatal("cannot decode the secret")
		}
		data = kv.Data
	} else if err := json.Unmarshal(answer.Data, &data); err != nil {
		t.Fatal("cannot decode the credential")
	}
	user, password = fields(data)
	if user == "" || password == "" {
		t.Fatal("the store gave no credential")
	}
	f, err := os.OpenFile(e2eEnv(t, "LIGO_E2E_SECRETS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintln(f, password); err != nil {
		t.Fatal(err)
	}
	return user, password
}

// storeCredential is a static credential, whose user is the spec's.
func storeCredential(t *testing.T, target string) (user, password string) {
	t.Helper()
	return storeRead(t, target, "secretPath", func(data map[string]string) (string, string) { return data["username"], data["password"] })
}

// TestServeLDAPLifecycle: OL-11, approved, the credential from the store
// connects and PostgreSQL verifies it against the directory; OL-12, rotated,
// the old one stops and the new one connects, still through the directory;
// OL-13, revoked, the account, the role and the credential are gone.
func TestServeLDAPLifecycle(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	dora.base = e2eEnv(t, "LIGO_E2E_ADMIN2")
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	source, target, binding := "ldap-src-"+x, "ldap-ledger-"+x, "ldap-"+x
	ldapSource(t, olga, dora, source, "w"+x)
	ldapTarget(t, olga, dora, target, "LEDGER_RO_ROLE")
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		t.Fatalf("binding: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	phase(t, olga, binding, "ACTIVE")

	user, first := storeCredential(t, target)
	reads(t, user, first)
	refused(t, "a wrong password", user, "not-"+first)
	exists, descriptions := account(t, user)
	if !exists || len(descriptions) != 1 || !strings.HasPrefix(descriptions[0], "ligo:binding_id=") {
		t.Errorf("OL-11: the account: %v %v", exists, descriptions)
	}

	if code, b := olga.do("POST", "/v1/admin/bindings/"+binding+"/rotate", map[string]any{}); code != http.StatusAccepted {
		t.Fatalf("rotate: %d %v", code, b)
	}
	b := phase(t, olga, binding, "ACTIVE")
	user2, second := storeCredential(t, target)
	if user2 != user || second == first {
		t.Fatalf("OL-12: after rotation the user is %q (was %q), the password changed: %v", user2, user, second != first)
	}
	reads(t, user, second) // through ligo_ldap: the reapply kept the membership
	refused(t, "OL-12: the old password", user, first)

	revoke(t, olga, dora, binding, b)
	revoked(t)
	if exists, _ := account(t, user); exists {
		t.Error("OL-13: the account is still in the directory")
	}
	if exists, _ := roleTag(t, targetAdmin(t), user); exists {
		t.Error("OL-13: the role is still on the target")
	}
	if conn, err := ledgerConn(t, user, second); err == nil {
		_ = conn.Close(context.Background())
		t.Error("OL-13: the credential still connects")
	}
}

// TestServeLDAPStageTwoFails is AC-10: the level's role is dropped before
// the binding is filed, so Stage 1 creates the account and Stage 2 creates the
// role and fails terminally at the grant. Deleting the binding removes both,
// from no artifact of Stage 2.
func TestServeLDAPStageTwoFails(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	dora.base = e2eEnv(t, "LIGO_E2E_ADMIN2")
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	source, target, binding := "ldap-gone-src-"+x, "ldap-gone-ledger-"+x, "ldap-gone-"+x
	admin, ctx := targetAdmin(t), context.Background()
	ident := pgx.Identifier{goneRole}.Sanitize()
	if _, err := admin.Exec(ctx, "DROP ROLE IF EXISTS "+ident); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE ROLE "+ident+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	ldapSource(t, olga, dora, source, "g"+x)
	ldapTarget(t, olga, dora, target, goneRole)
	if _, err := admin.Exec(ctx, "DROP ROLE "+ident); err != nil {
		t.Fatal(err)
	}

	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		t.Fatalf("binding: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	b := phase(t, olga, binding, "FAILED")
	id, err := uuid.Parse(b["metadata"].(map[string]any)["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := engine.DerivedPrincipalName(id, "")
	if err != nil {
		t.Fatal(err)
	}
	tag := "ligo:binding_id=" + id.String()
	if exists, descriptions := account(t, principal); !exists || len(descriptions) != 1 || descriptions[0] != tag {
		t.Fatalf("Stage 1 left no account of this binding: %v %v", exists, descriptions)
	}
	// Stage 2 is one transaction: its failure leaves no role (PG-8), and cleanup finds nothing to do
	if exists, comment := roleTag(t, admin, principal); exists {
		t.Fatalf("Stage 2 left a role: %q", comment)
	}

	revoke(t, olga, dora, binding, b)
	if exists, _ := account(t, principal); exists {
		t.Error("the account is still in the directory")
	}
	if exists, _ := roleTag(t, admin, principal); exists {
		t.Error("the role is still on the target")
	}
}
