package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	ligoID   = "spiffe://prod.lab/ns/sys/sa/ligo"
	serverID = "spiffe://prod.lab/ns/lab/sa/echo-server"
	boundID  = "spiffe://prod.lab/ns/echo/sa/bound"
)

func svid(t *testing.T, ca *spiffetest.CA, id string) *x509svid.SVID {
	t.Helper()
	w := ca.SVID(t, id)
	s, err := x509svid.ParseRaw(w.GetX509Svid(), w.GetX509SvidKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// serving is a server TLS configuration that presents id and requires a
// client SVID of the trust domain.
func serving(t *testing.T, ca *spiffetest.CA, bundle *x509bundle.Bundle, id string) *tls.Config {
	t.Helper()
	s := svid(t, ca, id)
	c := tlsconfig.MTLSServerConfig(s, bundle, tlsconfig.AuthorizeMemberOf(spiffeid.RequireTrustDomainFromString("prod.lab")))
	cert, err := tlsconfig.GetCertificate(s)(nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Certificates, c.GetCertificate = []tls.Certificate{*cert}, nil // httptest would add its own certificate otherwise
	return c
}

type env struct {
	ligo, bao, echo string
	deps            deps
	items           []map[string]any // what the workload API answers
	password        string           // the binding's password in OpenBao, and the echo server's
}

// setup starts a fake workload API, a fake OpenBao and an echo server that
// admits boundID, or the user bnd_x with the env's password.
func setup(t *testing.T, ligoAs, serverAs string) *env {
	t.Helper()
	ca := spiffetest.NewCA(t, "prod.lab")
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("prod.lab"), []*x509.Certificate{ca.Cert})
	v := &env{password: "s3cret"}

	wl := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/bindings" || r.URL.Query().Get("target") != "echo-svid-target" && r.URL.Query().Get("target") != "echo-local-target" {
			http.NotFound(w, r)
			return
		}
		items := v.items
		if items == nil {
			items = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	wl.TLS, wl.EnableHTTP2 = serving(t, ca, bundle, ligoAs), true
	wl.StartTLS()
	t.Cleanup(wl.Close)

	bao := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/jwt-spiffe/login":
			var b struct{ Role, JWT string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b.Role != "binding-1" || !forAudience(b.JWT, "https://bao-prod.ligo.lab") {
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/kv/data/bindings/1" && r.Header.Get("X-Vault-Token") == "tok":
			_, _ = fmt.Fprintf(w, `{"data":{"data":{"username":"bnd_x","password":%q}}}`, v.password)
		default:
			http.Error(w, "permission denied", http.StatusForbidden)
		}
	}))
	t.Cleanup(bao.Close)
	roots := x509.NewCertPool()
	roots.AddCert(bao.Certificate())

	l, err := tls.Listen("tcp", "127.0.0.1:0", serving(t, ca, bundle, serverAs))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				tc := conn.(*tls.Conn)
				if tc.Handshake() != nil {
					return
				}
				id, _ := x509svid.IDFromCert(tc.ConnectionState().PeerCertificates[0])
				in := bufio.NewScanner(conn)
				in.Scan()
				line, identity := in.Text(), id.String()
				if f := strings.Fields(line); len(f) == 3 && f[0] == "auth" {
					if f[1] != "bnd_x" || f[2] != "s3cret" {
						_, _ = fmt.Fprintln(conn, "denied")
						return
					}
					identity = f[1] + " " + identity
					in.Scan()
					line = in.Text()
				} else if identity != boundID {
					_, _ = fmt.Fprintln(conn, "denied")
					return
				}
				_, _ = fmt.Fprintf(conn, "%s\t%s\n", line, identity)
			}()
		}
	}()

	// JWT-SVIDs come from a fake SPIRE agent
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	agent := &spiffetest.Agent{Key: key, SVIDs: []*workload.X509SVID{ca.SVID(t, boundID)}, Bundles: map[string][]byte{"prod.lab": ca.Cert.Raw}}
	jwt, err := workloadapi.New(t.Context(), workloadapi.WithAddr(agent.Serve(t, t.TempDir(), "agent.sock")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jwt.Close() })

	v.ligo, v.bao, v.echo = strings.TrimPrefix(wl.URL, "https://"), bao.URL, l.Addr().String()
	v.deps = deps{X509: source{svid(t, ca, boundID), bundle}, JWT: jwt, Roots: roots}
	return v
}

// source is a fixed SVID with its trust domain's bundle.
type source struct {
	*x509svid.SVID
	*x509bundle.Bundle
}

// forAudience reports whether jwt's claims name audience.
func forAudience(jwt, audience string) bool {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Aud []string `json:"aud"`
		Sub string   `json:"sub"`
	}
	return err == nil && json.Unmarshal(raw, &claims) == nil && slices.Contains(claims.Aud, audience) && claims.Sub == boundID
}

func (v *env) run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(context.Background(), append([]string{"--ligo", v.ligo}, args...), &out, v.deps)
	return code, strings.TrimSpace(out.String())
}

func (v *env) svidBinding() map[string]any {
	return map[string]any{"name": "echo-bound-svid", "spec": map[string]string{"endpoint": v.echo, "serverId": serverID, "mode": "svid"},
		"auth": map[string]any{"secretStorageStrategy": "svid", "config": map[string]string{}}}
}

func (v *env) passwordBinding() map[string]any {
	return map[string]any{"name": "echo-bound-local", "spec": map[string]string{"endpoint": v.echo, "serverId": serverID, "mode": "password", "user": "bnd_x"},
		"auth": map[string]any{"secretStorageStrategy": "vault-static", "config": map[string]string{"address": v.bao, "audience": "https://bao-prod.ligo.lab",
			"secretPath": "kv/data/bindings/1", "authMount": "jwt-spiffe", "role": "binding-1", "policy": "binding-1"}}}
}

// TestBinding: no binding is exit 2; a binding in either mode echoes the
// message with the client's identity; a server that denies is exit 3.
func TestBinding(t *testing.T) {
	v := setup(t, ligoID, serverID)
	if code, out := v.run(t, "--target", "echo-svid-target"); code != exitNoBinding || out != "no binding" {
		t.Errorf("no binding: %d %q", code, out)
	}
	v.items = []map[string]any{v.svidBinding()}
	if code, out := v.run(t, "--target", "echo-svid-target", "--message", "hi there"); code != exitEchoed || !strings.HasSuffix(out, "hi there\t"+boundID) {
		t.Errorf("svid: %d %q", code, out)
	}
	v.items = []map[string]any{v.passwordBinding()}
	if code, out := v.run(t, "--target", "echo-local-target"); code != exitEchoed || !strings.HasSuffix(out, "hello\tbnd_x "+boundID) {
		t.Errorf("password: %d %q", code, out)
	}
	v.password = "rotated" // OpenBao and the server disagree: the server denies
	if code, out := v.run(t, "--target", "echo-local-target"); code != exitDenied || !strings.HasSuffix(out, "denied") {
		t.Errorf("a stale password: %d %q", code, out)
	}
}

// TestDirect: without ligo, an unlisted SVID or a wrong password is
// denied, the right credentials echo.
func TestDirect(t *testing.T) {
	v := setup(t, ligoID, serverID)
	if code, out := v.run(t, "--direct", v.echo); code != exitEchoed || out != "hello\t"+boundID {
		t.Errorf("direct svid: %d %q", code, out)
	}
	if code, out := v.run(t, "--direct", v.echo, "--mode", "password", "--user", "bnd_x", "--password", "nope"); code != exitDenied || out != "denied" {
		t.Errorf("direct wrong password: %d %q", code, out)
	}
	if code, _ := v.run(t, "--direct", v.echo, "--mode", "password", "--user", "bnd_x", "--password", "s3cret"); code != exitEchoed {
		t.Errorf("direct password: %d", code)
	}
}

// TestRefusals: the client talks only to ligo's and the server's SPIFFE
// IDs, needs a target, a one-line message and the binding's role.
func TestRefusals(t *testing.T) {
	impostor := setup(t, "spiffe://prod.lab/ns/x/sa/impostor", "spiffe://prod.lab/ns/x/sa/impostor")
	if code, out := impostor.run(t, "--target", "echo-svid-target"); code != exitError || !strings.Contains(out, "workload API") {
		t.Errorf("an impostor ligo: %d %q", code, out)
	}
	if code, out := impostor.run(t, "--direct", impostor.echo); code != exitError || !strings.Contains(out, "echo server") {
		t.Errorf("an impostor echo server: %d %q", code, out)
	}
	v := setup(t, ligoID, serverID)
	for name, args := range map[string][]string{"no target": {}, "two lines": {"--direct", v.echo, "--message", "a\nb"}, "bad mode": {"--direct", v.echo, "--mode", "x"},
		"bad transport": {"--direct", v.echo, "--transport", "soap"}} {
		if code, _ := v.run(t, args...); code != exitError {
			t.Errorf("%s: %d", name, code)
		}
	}
	b := v.passwordBinding()
	b["auth"].(map[string]any)["config"].(map[string]string)["role"] = "binding-2"
	v.items = []map[string]any{b}
	if code, out := v.run(t, "--target", "echo-local-target"); code != exitError || !strings.Contains(out, "login: 403") {
		t.Errorf("another binding's role: %d %q", code, out)
	}
}
