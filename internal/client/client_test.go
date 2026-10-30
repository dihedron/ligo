package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
)

// TestCredentials: the password file must be private to its owner; without
// one the prompt asks; a username is needed without a socket (§8.4).
func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pw")
	_ = os.WriteFile(file, []byte("s3cret\n"), 0o644)
	o := &Options{Username: "olivia", PasswordFile: file}
	if _, _, err := o.credentials(); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Errorf("a readable password file: %v", err)
	}
	_ = os.Chmod(file, 0o600)
	if u, p, err := o.credentials(); err != nil || u != "olivia" || p != "s3cret" {
		t.Errorf("password file: %q %q %v", u, p, err)
	}
	if _, _, err := (&Options{}).credentials(); err == nil {
		t.Error("no username and no socket")
	}
	asked := ""
	defer func(p func(string) (string, error)) { prompt = p }(prompt)
	prompt = func(user string) (string, error) { asked = user; return "typed", nil }
	if _, p, err := (&Options{Username: "olivia"}).credentials(); err != nil || p != "typed" || asked != "olivia" {
		t.Errorf("prompt: %q %v", p, err)
	}
	if _, _, err := (&Options{Username: "olivia", PasswordFile: filepath.Join(dir, "none")}).credentials(); err == nil {
		t.Error("a missing password file")
	}
}

// caFile writes srv's certificate as a PEM bundle for --ca-cert.
func caFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	return file
}

// TestDo: Basic credentials on every request, the server verified with
// --ca-cert, JSON both ways, and problems as *Problem.
func TestDo(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		switch {
		case user != "olivia" || pass != "pw":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"type":"urn:ligo:problem:unauthenticated","title":"Unauthorized","status":401,"detail":"valid credentials are required"}`))
		case r.URL.Path == "/v1/admin/echo":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			_ = json.NewEncoder(w).Encode(map[string]any{"method": r.Method, "q": r.URL.Query().Get("q"), "in": in})
		default:
			w.WriteHeader(502)
			_, _ = w.Write([]byte("bad gateway"))
		}
	}))
	defer srv.Close()
	pw := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(pw, []byte("pw"), 0o600)
	ctx := context.Background()
	c, err := (&Options{ServerURL: srv.URL, CACert: caFile(t, srv), Username: "olivia", PasswordFile: pw}).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var out map[string]any
	if err := c.Do(ctx, "POST", "/v1/admin/echo", map[string][]string{"q": {"x"}}, map[string]string{"a": "b"}, &out); err != nil ||
		out["method"] != "POST" || out["q"] != "x" || out["in"].(map[string]any)["a"] != "b" {
		t.Errorf("echo: %v %v", out, err)
	}
	var p *Problem
	if err := c.Do(ctx, "GET", "/v1/admin/other", nil, nil, nil); !errors.As(err, &p) || p.Status != 502 || p.Detail != "bad gateway" {
		t.Errorf("not a problem body: %v", err)
	}
	c.pass = "wrong"
	if err := c.Do(ctx, "GET", "/v1/admin/echo", nil, nil, nil); !errors.As(err, &p) || p.Status != 401 ||
		p.Error() != "401 unauthenticated: valid credentials are required" {
		t.Errorf("problem: %v", err)
	}
	for _, bad := range []*Options{{ServerURL: "http://ligo:9443", Username: "u", PasswordFile: pw}, {ServerURL: srv.URL, CACert: pw, Username: "u", PasswordFile: pw}} {
		if _, err := bad.Connect(ctx); err == nil {
			t.Errorf("connect %+v", bad)
		}
	}
}

// TestSVID: with --spiffe-socket the client presents its SVID and accepts
// only the server whose SVID is --server-id (by default ligo's in the
// client's trust domain), verified with the socket's bundle.
func TestSVID(t *testing.T) {
	dir, err := os.MkdirTemp("", "ligo-client") // short: unix socket paths are limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ca := spiffetest.NewCA(t, "prod.lab")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	agent := &spiffetest.Agent{Key: key, SVIDs: []*workload.X509SVID{ca.SVID(t, "spiffe://prod.lab/ops/olga")},
		Bundles: map[string][]byte{"prod.lab": ca.Cert.Raw}}
	socket := agent.Serve(t, dir, "prod")
	server := func(id string) *httptest.Server {
		svid := ca.SVID(t, id)
		k, _ := x509.ParsePKCS8PrivateKey(svid.GetX509SvidKey())
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"client": r.TLS.PeerCertificates[0].URIs[0].String()})
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{svid.GetX509Svid()}, PrivateKey: k}}, ClientAuth: tls.RequireAnyClientCert}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	ctx := context.Background()
	ligo := server("spiffe://prod.lab/ns/sys/sa/ligo")
	c, err := (&Options{ServerURL: ligo.URL, SpiffeSocket: socket}).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := c.Do(ctx, "GET", "/v1/admin/x", nil, nil, &out); err != nil || out["client"] != "spiffe://prod.lab/ops/olga" {
		t.Errorf("SVID mTLS: %v %v", out, err)
	}
	c.Close()
	impostor := server("spiffe://prod.lab/ns/apps/sa/other")
	c, err = (&Options{ServerURL: impostor.URL, SpiffeSocket: socket}).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Do(ctx, "GET", "/v1/admin/x", nil, nil, nil); err == nil {
		t.Error("a server with another SPIFFE ID was accepted")
	}
	c.Close()
	c, err = (&Options{ServerURL: impostor.URL, SpiffeSocket: socket, ServerID: "spiffe://prod.lab/ns/apps/sa/other"}).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Do(ctx, "GET", "/v1/admin/x", nil, nil, nil); err != nil {
		t.Errorf("--server-id: %v", err)
	}
	c.Close()
	if _, err := (&Options{ServerURL: ligo.URL, SpiffeSocket: socket, ServerID: "not an id"}).Connect(ctx); err == nil {
		t.Error("an invalid --server-id")
	}
}

// TestPrint: JSON and YAML as they are; tables from columns over items,
// with the next page's token.
func TestPrint(t *testing.T) {
	var v any
	_ = json.Unmarshal([]byte(`{"items":[{"metadata":{"name":"a","labels":{"k":"v"}},"roles":["x","y"],"n":2,"empty":""},{"metadata":{"name":"b"}}],
		"nextPageToken":"tok"}`), &v)
	var b bytes.Buffer
	cols := []Column{{"NAME", "metadata.name"}, {"ROLES", "roles"}, {"N", "n"}, {"LABELS", "metadata.labels"}, {"EMPTY", "empty"}, {"MISSING", "x.y"}}
	if err := Print(&b, "table", v, cols...); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[0], "NAME") || strings.Join(strings.Fields(lines[1]), " ") != `a x,y 2 {"k":"v"} - -` ||
		strings.Join(strings.Fields(lines[2]), " ") != "b - - - - -" || lines[4] != "next page: --page-token tok" {
		t.Errorf("table:\n%s", b.String())
	}
	for format, want := range map[string]string{"json": `"nextPageToken": "tok"`, "yaml": "nextPageToken: tok"} {
		b.Reset()
		if err := Print(&b, format, v); err != nil || !strings.Contains(b.String(), want) {
			t.Errorf("%s: %s %v", format, b.String(), err)
		}
	}
	b.Reset()
	if err := Print(&b, "table", map[string]any{"policy": "p"}); err != nil || !strings.Contains(b.String(), "policy: p") {
		t.Errorf("no columns: %s", b.String())
	}
}
