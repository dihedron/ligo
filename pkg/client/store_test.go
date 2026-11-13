package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
)

const (
	storePassword = "p4ss-w0rd-s3cret"
	dynPassword   = "dyn-p4ss-s3cret"
)

// fakeStore is a Vault-compatible store with one static secret and one
// database role.
type fakeStore struct {
	srv       *httptest.Server
	logins    []map[string]string // role, jwt
	spaces    []string            // X-Vault-Namespace of each request
	tokens    map[string]bool     // valid tokens
	loginCode int                 // when not 0, logins answer it
	readBody  string              // when set, reads answer it
	lease     int
	reads     int
}

func newStore(t *testing.T) *fakeStore {
	t.Helper()
	f := &fakeStore{tokens: map[string]bool{}, lease: 300}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.spaces = append(f.spaces, r.Header.Get("X-Vault-Namespace"))
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/auth/jwt/login":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			f.logins = append(f.logins, in)
			if f.loginCode != 0 {
				http.Error(w, `{"errors":["login refused for `+in["jwt"]+`"]}`, f.loginCode)
				return
			}
			token := fmt.Sprintf("hvs.token-%d", len(f.logins))
			f.tokens[token] = true
			_, _ = fmt.Fprintf(w, `{"auth":{"client_token":%q,"lease_duration":600}}`, token)
		case "GET /v1/kv/data/bindings/0192", "GET /v1/database/creds/binding-0192":
			f.reads++
			if !f.tokens[r.Header.Get("X-Vault-Token")] {
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
				return
			}
			switch {
			case f.readBody != "":
				_, _ = w.Write([]byte(f.readBody))
			case strings.HasPrefix(r.URL.Path, "/v1/kv/"):
				_, _ = fmt.Fprintf(w, `{"data":{"data":{"username":"bnd_x","password":%q}}}`, storePassword)
			default:
				_, _ = fmt.Fprintf(w, `{"lease_duration":%d,"data":{"username":"v-dyn-1","password":%q}}`, f.lease, dynPassword)
			}
		case "GET /v1/redirect":
			http.Redirect(w, r, "https://elsewhere.invalid/v1/kv", http.StatusTemporaryRedirect)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeStore) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	return pool
}

func (f *fakeStore) binding(strategy string) Binding {
	cfg := map[string]string{"address": f.srv.URL, "audience": "https://vault.lab", "authMount": "jwt", "role": "binding-0192", "policy": "binding-0192"}
	if strategy == strategyDynamic {
		cfg["credsPath"] = "database/creds/binding-0192"
	} else {
		cfg["secretPath"] = "kv/data/bindings/0192"
	}
	return Binding{Name: "workers-ledger", Target: "ledger", Auth: Auth{Strategy: strategy, StoreType: "vault", Config: cfg}}
}

// storeClient is a client that takes its JWT-SVIDs from a fake agent, logs
// at debug level into the returned buffer, and has a clock the test moves.
func storeClient(t *testing.T, v *env, f *fakeStore, allowed ...string) (*Client, *bytes.Buffer, *time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	agent := &spiffetest.Agent{Key: key, SVIDs: []*workload.X509SVID{v.ca.SVID(t, workerID)}, Bundles: map[string][]byte{"prod.lab": v.ca.Cert.Raw}}
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", agent.Serve(t, t.TempDir(), "agent.sock"))
	logs := &bytes.Buffer{}
	c, err := New(t.Context(), Config{Address: "ligo.lab:8443", ServerID: ligoID, X509Source: v.source, StoreRoots: f.roots(), AllowedStores: allowed,
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	now := time.Now()
	c.now = func() time.Time { return now }
	return c, logs, &now
}

// claims decodes a JWT's payload.
func claims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestCredential is CS-6 and CS-7.
func TestCredential(t *testing.T) {
	v, f := newEnv(t), newStore(t)
	c, _, now := storeClient(t, v, f)
	static, err := c.Credential(t.Context(), f.binding(strategyStatic))
	if err != nil || static != (Credential{Username: "bnd_x", Password: storePassword}) {
		t.Fatalf("static: %+v (%v)", static.Username, err)
	}
	if len(f.logins) != 1 || f.logins[0]["role"] != "binding-0192" {
		t.Fatalf("logins %d", len(f.logins))
	}
	if cl := claims(t, f.logins[0]["jwt"]); fmt.Sprint(cl["aud"]) != "[https://vault.lab]" || cl["sub"] != workerID {
		t.Errorf("JWT claims %v", cl)
	}
	dyn, err := c.Credential(t.Context(), f.binding(strategyDynamic))
	if err != nil || dyn.Username != "v-dyn-1" || dyn.Password != dynPassword || !dyn.Expires.Equal(now.Add(300*time.Second)) {
		t.Errorf("dynamic: %s (%v)", dyn, err)
	}
}

// TestNamespace: a binding's namespace is sent on the login and on the
// read, and a login in one namespace is not used in another.
func TestNamespace(t *testing.T) {
	v, f := newEnv(t), newStore(t)
	c, _, _ := storeClient(t, v, f)
	in := func(ns string) Binding {
		b := f.binding(strategyStatic)
		if ns != "" {
			b.Auth.Config["namespace"] = ns
		}
		return b
	}
	for _, ns := range []string{"", "team-a", "team-a", "team-b"} {
		if _, err := c.Credential(t.Context(), in(ns)); err != nil {
			t.Fatal(err)
		}
	}
	// login+read, login+read, read, login+read
	if want := []string{"", "", "team-a", "team-a", "team-a", "team-b", "team-b"}; !reflect.DeepEqual(f.spaces, want) || len(f.logins) != 3 {
		t.Errorf("namespaces %q, %d logins", f.spaces, len(f.logins))
	}
	c.Invalidate(in("team-a"))
	if _, err := c.Credential(t.Context(), in("team-a")); err != nil || len(f.logins) != 4 {
		t.Errorf("after Invalidate: %d logins (%v)", len(f.logins), err)
	}
}

// TestStoreToken is CS-8.
func TestStoreToken(t *testing.T) {
	v, f := newEnv(t), newStore(t)
	c, _, now := storeClient(t, v, f)
	b := f.binding(strategyStatic)
	read := func(wantLogins int, what string) {
		t.Helper()
		if _, err := c.Credential(t.Context(), b); err != nil || len(f.logins) != wantLogins {
			t.Fatalf("%s: %d logins (%v)", what, len(f.logins), err)
		}
	}
	read(1, "first")
	*now = now.Add(479 * time.Second)
	read(1, "before 80 % of 600 s")
	*now = now.Add(2 * time.Second)
	read(2, "after 80 % of the TTL")
	clear(f.tokens) // the store revokes the token
	reads := f.reads
	read(3, "a 403 with a remembered token")
	if f.reads != reads+2 {
		t.Errorf("%d reads for one retry", f.reads-reads)
	}
	c.Invalidate(b)
	read(4, "after Invalidate")
	_ = c.Close()
	if len(c.tokens) != 0 {
		t.Error("Close kept the tokens")
	}
}

// TestCredentialRefusals is CS-9.
func TestCredentialRefusals(t *testing.T) {
	v, f := newEnv(t), newStore(t)
	c, _, _ := storeClient(t, v, f)
	with := func(strategy string, change func(*Binding)) Binding {
		b := f.binding(strategy)
		change(&b)
		return b
	}
	set := func(k, val string) func(*Binding) { return func(b *Binding) { b.Auth.Config[k] = val } }
	for name, tc := range map[string]struct {
		b    Binding
		is   error
		text string
	}{
		"no store":          {with("", func(*Binding) {}), ErrNoCredential, "no credential"},
		"the SVID strategy": {with("svid", func(*Binding) {}), ErrNoCredential, "no credential"},
		"unknown strategy":  {with("cyberark", func(*Binding) {}), ErrUnsupportedStrategy, "cyberark"},
		"no audience":       {with(strategyStatic, set("audience", "")), ErrStore, "no audience"},
		"no address":        {with(strategyStatic, set("address", "")), ErrStore, "no address"},
		"no role":           {with(strategyDynamic, set("role", "")), ErrStore, "no role"},
		"no path":           {with(strategyDynamic, set("credsPath", "")), ErrStore, "no path"},
		"static with creds": {with(strategyStatic, func(b *Binding) { b.Auth.Config = f.binding(strategyDynamic).Auth.Config }), ErrStore, "no path"},
		"http":              {with(strategyStatic, set("address", strings.Replace(f.srv.URL, "https://", "http://", 1))), ErrStoreNotAllowed, "https://host:port"},
		"address with path": {with(strategyStatic, set("address", f.srv.URL+"/v1/sys")), ErrStoreNotAllowed, "https://host:port"},
		"address with user": {with(strategyStatic, set("address", strings.Replace(f.srv.URL, "https://", "https://u:p@", 1))), ErrStoreNotAllowed, "https://host:port"},
		"unknown path":      {with(strategyStatic, set("secretPath", "kv/data/bindings/other")), ErrStore, "404"},
		"a redirect":        {with(strategyStatic, set("secretPath", "redirect")), ErrStore, "307"},
		"nobody listens":    {with(strategyStatic, set("address", "https://127.0.0.1:1")), ErrStore, "login"},
	} {
		_, err := c.Credential(t.Context(), tc.b)
		if !errors.Is(err, tc.is) || !strings.Contains(err.Error(), tc.text) || !strings.Contains(err.Error(), "workers-ledger") {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, tc := range map[string]struct{ body, text string }{
		"not JSON":       {"<html>", "not a secret"},
		"no password":    {`{"data":{"data":{"username":"u"}}}`, "no username and password"},
		"too large":      {`{"pad":"` + strings.Repeat("x", maxBody) + `"}`, "larger than"},
		"no lease":       {`{"data":{"username":"u","password":"p"}}`, "lease"},
		"a huge lease":   {`{"lease_duration":9000000000000,"data":{"username":"u","password":"p"}}`, "lease"},
		"dynamic no pwd": {`{"lease_duration":60,"data":{"username":"u"}}`, "no username and password"},
	} {
		f.readBody = tc.body
		strategy := strategyStatic
		if strings.Contains(name, "lease") || strings.Contains(name, "dynamic") {
			strategy = strategyDynamic
		}
		if _, err := c.Credential(t.Context(), f.binding(strategy)); !errors.Is(err, ErrStore) || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.readBody = ""

	// a fresh token that the store refuses is not tried again
	denied := f.binding(strategyStatic)
	denied.Auth.Config["role"] = "another-role"
	original := f.srv.Config.Handler
	f.srv.Config.Handler = func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				f.reads++
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			inner.ServeHTTP(w, r)
		})
	}(f.srv.Config.Handler)
	reads := f.reads
	if _, err := c.Credential(t.Context(), denied); !errors.Is(err, ErrStore) || !strings.Contains(err.Error(), "read: 403") || f.reads != reads+1 {
		t.Errorf("a fresh token refused: %v, %d reads", err, f.reads-reads)
	}
	f.srv.Config.Handler = original

	f.loginCode = http.StatusForbidden
	c.Invalidate(f.binding(strategyStatic))
	if _, err := c.Credential(t.Context(), f.binding(strategyStatic)); !errors.Is(err, ErrStore) || !strings.Contains(err.Error(), "login: 403") {
		t.Errorf("login refused: %v", err)
	}

	// a certificate outside StoreRoots
	other, _, _ := storeClient(t, v, f)
	pool := x509.NewCertPool()
	pool.AddCert(v.ca.Cert)
	other.storeHTTP = newStoreHTTP(pool)
	if _, err := other.Credential(t.Context(), f.binding(strategyStatic)); !errors.Is(err, ErrStore) || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unknown CA: %v", err)
	}

	// AllowedStores
	if _, err := New(t.Context(), Config{Address: "ligo.lab:8443", ServerID: ligoID, X509Source: v.source, AllowedStores: []string{"vault.lab:8200"}}); err == nil || !strings.Contains(err.Error(), "AllowedStores") {
		t.Errorf("AllowedStores without a scheme: %v", err)
	}
	f.loginCode = 0
	pinned, _, _ := storeClient(t, v, f, "https://vault.lab:8200", "https://VAULT2.lab")
	if _, err := pinned.Credential(t.Context(), f.binding(strategyStatic)); !errors.Is(err, ErrStoreNotAllowed) || !strings.Contains(err.Error(), "AllowedStores") {
		t.Errorf("a store outside AllowedStores: %v", err)
	}
	if !pinned.allowedStores["https://vault2.lab:443"] {
		t.Errorf("AllowedStores %v", pinned.allowedStores)
	}
	logins := len(f.logins)
	allowed, _, _ := storeClient(t, v, f, f.srv.URL+"/")
	if _, err := allowed.Credential(t.Context(), f.binding(strategyStatic)); err != nil || len(f.logins) != logins+1 {
		t.Errorf("an allowed store: %v", err)
	}
}

// TestNoSecretLeaks is CS-10: no log line and no error holds a password, a
// store token or a JWT-SVID.
func TestNoSecretLeaks(t *testing.T) {
	v, f := newEnv(t), newStore(t)
	c, logs, _ := storeClient(t, v, f)
	var said []string
	say := func(cred Credential, err error) {
		said = append(said, fmt.Sprint(cred), fmt.Sprintf("%v %+v %#v %s", cred, cred, cred, cred), fmt.Sprint(err))
		c.log.Info("credential", "credential", cred, "error", err)
	}
	say(c.Credential(t.Context(), f.binding(strategyStatic)))
	say(c.Credential(t.Context(), f.binding(strategyDynamic)))
	f.readBody = `{"data":{"data":{"username":"u","password":""},"leak":"` + storePassword + `"}}`
	say(c.Credential(t.Context(), f.binding(strategyStatic)))
	f.readBody, f.loginCode = "", http.StatusBadRequest // the fake's error body repeats the JWT
	c.Invalidate(f.binding(strategyStatic))
	say(c.Credential(t.Context(), f.binding(strategyStatic)))
	if len(f.logins) < 2 || !strings.Contains(logs.String(), "store login") {
		t.Fatalf("%d logins, logs %q", len(f.logins), logs)
	}
	secrets := []string{storePassword, dynPassword, "hvs.token-1"}
	for _, l := range f.logins {
		secrets = append(secrets, l["jwt"])
	}
	for _, text := range append(said, logs.String()) {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("%q leaks in %q", s, text)
			}
		}
	}
	if !strings.Contains(said[0], "bnd_x") || !strings.Contains(said[0], "[hidden]") {
		t.Errorf("String: %q", said[0])
	}
}

func FuzzStoreResponse(f *testing.F) {
	f.Add([]byte(`{"auth":{"client_token":"t","lease_duration":600}}`))
	f.Add([]byte(`{"data":{"data":{"username":"u","password":"p"}}}`))
	f.Add([]byte(`{"lease_duration":300,"data":{"username":"u","password":"p"}}`))
	f.Add([]byte(`{"lease_duration":-1,"auth":null,"data":[]}`))
	now := time.Now()
	f.Fuzz(func(t *testing.T, body []byte) {
		if token, ttl, err := parseLogin(body); err == nil && (token == "" || ttl < 0) {
			t.Errorf("login: %q %s", token, ttl)
		}
		for _, strategy := range []string{strategyStatic, strategyDynamic} {
			cred, err := parseSecret(strategy, body, now)
			if err == nil && (cred.Username == "" || cred.Password == "" || strategy == strategyDynamic && !cred.Expires.After(now)) {
				t.Errorf("%s: %s", strategy, cred)
			}
		}
	})
}

func FuzzBindingsDocument(f *testing.F) {
	f.Add([]byte(bindingsBody))
	f.Add([]byte(`{"items":[{"auth":{"config":{"a":1,"b":[true],"c":null}},"spec":null}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var doc struct {
			Items []wireBinding `json:"items"`
		}
		if json.Unmarshal(body, &doc) != nil {
			return
		}
		for _, w := range doc.Items {
			b := w.binding()
			_ = b.Endpoint()
			if len(b.Auth.Config) != len(w.Auth.Config) {
				t.Errorf("config %v from %v", b.Auth.Config, w.Auth.Config)
			}
		}
	})
}
