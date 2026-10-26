package pluginsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixedJWT string

func (j fixedJWT) FetchJWT(context.Context) (string, error) { return string(j), nil }

// fakeVault serves a JWT login, a KV v2 secret and database static
// credentials, counting reads; refuse fails every login.
type fakeVault struct {
	*httptest.Server
	reads     int
	namespace string
	refuse    bool
	ttl       int
}

func newFakeVault(t *testing.T) *fakeVault {
	v := &fakeVault{ttl: 100}
	v.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.namespace = r.Header.Get("X-Vault-Namespace")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/jwt-spiffe/login":
			var body struct{ Role, JWT string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			if v.refuse || body.Role != "ligo-plugin-pg" || body.JWT != "the-jwt" {
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
				return
			}
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"tok","lease_duration":3600}}`)
		case r.Header.Get("X-Vault-Token") != "tok":
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		case r.URL.Path == "/v1/kv/data/ligo/bootstrap/pg":
			v.reads++
			_, _ = fmt.Fprintf(w, `{"data":{"data":{"username":"admin","password":"kv-pass-%d"}}}`, v.reads)
		case r.URL.Path == "/v1/database/static-creds/pg-admin":
			v.reads++
			_, _ = fmt.Fprintf(w, `{"data":{"username":"admin","password":"db-pass-%d","ttl":%d}}`, v.reads, v.ttl)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(v.Close)
	return v
}

func bootstrapConfig(v *fakeVault) BootstrapCredentialConfig {
	return BootstrapCredentialConfig{
		Source: "vault", Address: v.URL, AuthMount: "jwt-spiffe", Role: "ligo-plugin-pg",
		JWTAudience: "https://vault", KVPath: "kv/data/ligo/bootstrap/pg",
	}
}

func TestBootstrapConfigValidate(t *testing.T) {
	good := BootstrapCredentialConfig{Source: "vault", Address: "https://v:8200", AuthMount: "jwt", Role: "r", JWTAudience: "a", KVPath: "kv/data/x"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*BootstrapCredentialConfig){
		"source":       func(c *BootstrapCredentialConfig) { c.Source = "file" },
		"address":      func(c *BootstrapCredentialConfig) { c.Address = "v:8200" },
		"plain http":   func(c *BootstrapCredentialConfig) { c.Address = "http://v:8200" },
		"auth_mount":   func(c *BootstrapCredentialConfig) { c.AuthMount = "" },
		"role":         func(c *BootstrapCredentialConfig) { c.Role = "" },
		"jwt_audience": func(c *BootstrapCredentialConfig) { c.JWTAudience = "" },
		"both paths":   func(c *BootstrapCredentialConfig) { c.DBStaticRole = "r" },
		"no path":      func(c *BootstrapCredentialConfig) { c.KVPath = "" },
	} {
		c := good
		change(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewBootstrapCredential(BootstrapCredentialConfig{}, fixedJWT("x"), nil); err == nil {
		t.Error("NewBootstrapCredential accepted an invalid config")
	}
}

// TestBootstrapKV: a KV v2 credential, re-read only after the refresh
// interval, sent with the namespace.
func TestBootstrapKV(t *testing.T) {
	v := newFakeVault(t)
	cfg := bootstrapConfig(v)
	cfg.Namespace = "prod"
	b, err := NewBootstrapCredential(cfg, fixedJWT("the-jwt"), v.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	b.now = func() time.Time { return now }
	ctx := context.Background()
	c, err := b.Get(ctx)
	if err != nil || c.Username != "admin" || c.Password.Reveal() != "kv-pass-1" || v.namespace != "prod" {
		t.Fatalf("Get = (%+v, %v), namespace %q", c, err, v.namespace)
	}
	now = now.Add(kvRefresh - time.Second)
	if c, _ := b.Get(ctx); c.Password.Reveal() != "kv-pass-1" {
		t.Error("re-read before the refresh interval")
	}
	now = now.Add(time.Second)
	if c, _ := b.Get(ctx); c.Password.Reveal() != "kv-pass-2" {
		t.Error("not re-read after the refresh interval")
	}
}

// TestBootstrapDBStatic: database static credentials, renewed at 80% of
// their ttl (§5.5 "renewed per Vault lease").
func TestBootstrapDBStatic(t *testing.T) {
	v := newFakeVault(t)
	cfg := bootstrapConfig(v)
	cfg.KVPath, cfg.DBStaticRole = "", "pg-admin"
	b, err := NewBootstrapCredential(cfg, fixedJWT("the-jwt"), v.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	b.now = func() time.Time { return now }
	ctx := context.Background()
	if c, err := b.Get(ctx); err != nil || c.Password.Reveal() != "db-pass-1" {
		t.Fatalf("Get = (%+v, %v)", c, err)
	}
	now = now.Add(79 * time.Second)
	if c, _ := b.Get(ctx); c.Password.Reveal() != "db-pass-1" {
		t.Error("renewed before 80% of the ttl")
	}
	now = now.Add(time.Second)
	if c, _ := b.Get(ctx); c.Password.Reveal() != "db-pass-2" {
		t.Error("not renewed at 80% of the ttl")
	}
}

// TestBootstrapErrors: a refused login, a missing secret and a malformed
// one fail, and no error carries the response or the token.
func TestBootstrapErrors(t *testing.T) {
	v := newFakeVault(t)
	ctx := context.Background()

	v.refuse = true
	b, _ := NewBootstrapCredential(bootstrapConfig(v), fixedJWT("the-jwt"), v.Client())
	if _, err := b.Get(ctx); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("refused login: %v", err)
	}
	v.refuse = false

	cfg := bootstrapConfig(v)
	cfg.KVPath = "kv/data/missing"
	b, _ = NewBootstrapCredential(cfg, fixedJWT("the-jwt"), v.Client())
	if _, err := b.Get(ctx); err == nil || strings.Contains(err.Error(), "tok") {
		t.Errorf("missing secret: %v", err)
	}

	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = io.WriteString(w, `{"auth":{"client_token":"tok"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"data":{"username":"admin"}}}`)
	}))
	defer bad.Close()
	cfg = bootstrapConfig(v)
	cfg.Address = bad.URL
	b, _ = NewBootstrapCredential(cfg, fixedJWT("the-jwt"), bad.Client())
	if _, err := b.Get(ctx); err == nil {
		t.Error("a credential without a password was accepted")
	}
}

// TestSecretRedacted: a Secret never prints, logs or marshals its value.
func TestSecretRedacted(t *testing.T) {
	c := Credential{Username: "admin", Password: Secret("hunter2")}
	var log strings.Builder
	slog.New(slog.NewJSONHandler(&log, nil)).Info("x", "credential", c.Password, "c", c)
	js, _ := json.Marshal(c)
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), log.String(), string(js)} {
		if strings.Contains(s, "hunter2") {
			t.Errorf("secret leaked: %s", s)
		}
	}
	if c.Password.Reveal() != "hunter2" {
		t.Error("Reveal")
	}
}
