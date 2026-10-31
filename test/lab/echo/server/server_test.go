package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	serverID  = "spiffe://prod.lab/ns/lab/sa/echo-server"
	pluginID  = "spiffe://prod.lab/ligo/plugin/target-echo"
	boundID   = "spiffe://prod.lab/ns/echo/sa/bound"
	unboundID = "spiffe://prod.lab/ns/echo/sa/unbound"
	bindingID = "01a19270-0000-7000-8000-000000000001"
)

type env struct {
	ca      *spiffetest.CA
	bundle  *x509bundle.Bundle
	data    string
	control string
	state   string
	cancel  context.CancelFunc
}

func svid(t *testing.T, ca *spiffetest.CA, id string) *x509svid.SVID {
	t.Helper()
	w := ca.SVID(t, id)
	s, err := x509svid.ParseRaw(w.GetX509Svid(), w.GetX509SvidKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// start runs a server in mode on loopback ports, with state in dir.
func start(t *testing.T, mode, dir string, ca *spiffetest.CA) *env {
	t.Helper()
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("prod.lab"), []*x509.Certificate{ca.Cert})
	s := &Server{Mode: mode, TrustDomain: spiffeid.RequireTrustDomainFromString("prod.lab"), ControlID: spiffeid.RequireFromString(pluginID),
		StatePath: filepath.Join(dir, "state.json"), SVIDs: svid(t, ca, serverID), Bundles: bundle, Log: slog.New(slog.DiscardHandler)}
	if err := s.load(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	dl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ctx, dl) }()
	cs := s.Control()
	go func() { _ = cs.ServeTLS(cl, "", "") }()
	t.Cleanup(func() { cancel(); _ = cs.Close() })
	return &env{ca: ca, bundle: bundle, data: dl.Addr().String(), control: cl.Addr().String(), state: s.StatePath, cancel: cancel}
}

// talk sends lines over TLS as id ("" for no client certificate) and
// returns the answer, or the error.
func (v *env) talk(t *testing.T, id string, lines ...string) (string, error) {
	t.Helper()
	auth := tlsconfig.AuthorizeID(spiffeid.RequireFromString(serverID))
	cfg := tlsconfig.TLSClientConfig(v.bundle, auth)
	if id != "" {
		cfg = tlsconfig.MTLSClientConfig(svid(t, v.ca, id), v.bundle, auth)
	}
	conn, err := tls.Dial("tcp", v.data, cfg)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.Handshake(); err != nil {
		return "", err
	}
	for _, l := range lines {
		if _, err := conn.Write([]byte(l + "\n")); err != nil {
			return "", err
		}
	}
	answer, err := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSuffix(answer, "\n"), err
}

// controlCall calls the control API as id.
func (v *env) controlCall(t *testing.T, id, method, path, body string) (int, error) {
	t.Helper()
	cfg := tlsconfig.MTLSClientConfig(svid(t, v.ca, id), v.bundle, tlsconfig.AuthorizeID(spiffeid.RequireFromString(serverID)))
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	req, _ := http.NewRequest(method, "https://"+v.control+path, bytes.NewBufferString(body))
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// TestSVIDMode: only client SVIDs matching the access list are echoed with
// their SPIFFE ID; target-echo alone changes the list, which survives a
// restart.
func TestSVIDMode(t *testing.T) {
	ca, dir := spiffetest.NewCA(t, "prod.lab"), t.TempDir()
	v := start(t, ModeSVID, dir, ca)
	if got, _ := v.talk(t, boundID, "hello"); got != "denied" {
		t.Errorf("before the binding: %q", got)
	}
	if _, err := v.talk(t, "", "hello"); err == nil {
		t.Error("a client without an SVID was served")
	}
	if code, err := v.controlCall(t, boundID, "PUT", "/acl/"+bindingID, `{"regex":".*"}`); err == nil && code < 400 {
		t.Errorf("a workload changed the access list: %d", code)
	}
	for body, want := range map[string]int{`{"regex":"("}`: 422, `not json`: 422, `{"regex":"^spiffe://prod\\.lab/ns/echo/sa/bound$"}`: 204} {
		if code, err := v.controlCall(t, pluginID, "PUT", "/acl/"+bindingID, body); err != nil || code != want {
			t.Errorf("PUT %s: %d %v, want %d", body, code, err, want)
		}
	}
	if code, _ := v.controlCall(t, pluginID, "PUT", "/acl/not-an-id", `{"regex":".*"}`); code != 422 {
		t.Errorf("bad binding ID: %d", code)
	}
	if got, err := v.talk(t, boundID, "hello there"); got != "hello there\t"+boundID || err != nil {
		t.Errorf("bound: %q %v", got, err)
	}
	if got, _ := v.talk(t, unboundID, "hello"); got != "denied" {
		t.Errorf("unbound: %q", got)
	}

	v.cancel()
	v = start(t, ModeSVID, dir, ca) // restarted on the same state
	if got, _ := v.talk(t, boundID, "again"); got != "again\t"+boundID {
		t.Errorf("after a restart: %q", got)
	}
	if code, err := v.controlCall(t, pluginID, "DELETE", "/acl/"+bindingID, ""); err != nil || code != 204 {
		t.Errorf("DELETE: %d %v", code, err)
	}
	if got, _ := v.talk(t, boundID, "hello"); got != "denied" {
		t.Errorf("after the revocation: %q", got)
	}
}

// TestPasswordMode: a user with its password is echoed with the user and,
// when given, the client's SPIFFE ID; anything else is denied.
func TestPasswordMode(t *testing.T) {
	v := start(t, ModePassword, t.TempDir(), spiffetest.NewCA(t, "prod.lab"))
	if got, _ := v.talk(t, boundID, "auth bnd_x secret", "hello"); got != "denied" {
		t.Errorf("before the user exists: %q", got)
	}
	if code, err := v.controlCall(t, pluginID, "PUT", "/users/bnd_x", `{"password":"secret"}`); err != nil || code != 204 {
		t.Fatalf("PUT user: %d %v", code, err)
	}
	for _, bad := range []string{"/users/bad-name", "/users/bnd_y"} {
		body := `{"password":"secret"}`
		if bad == "/users/bnd_y" {
			body = `{"password":""}`
		}
		if code, _ := v.controlCall(t, pluginID, "PUT", bad, body); code != 422 {
			t.Errorf("PUT %s: %d", bad, code)
		}
	}
	if got, err := v.talk(t, boundID, "auth bnd_x secret", "hello"); got != "hello\tbnd_x "+boundID || err != nil {
		t.Errorf("with an SVID: %q %v", got, err)
	}
	if got, err := v.talk(t, "", "auth bnd_x secret", "hello"); got != "hello\tbnd_x" || err != nil {
		t.Errorf("without an SVID: %q %v", got, err)
	}
	for _, auth := range []string{"auth bnd_x wrong", "auth nobody secret", "hello"} {
		if got, _ := v.talk(t, "", auth, "hello"); got != "denied" {
			t.Errorf("%q: %q", auth, got)
		}
	}
	if code, _ := v.controlCall(t, pluginID, "DELETE", "/users/bnd_x", ""); code != 204 {
		t.Errorf("DELETE user: %d", code)
	}
	if got, _ := v.talk(t, "", "auth bnd_x secret", "hello"); got != "denied" {
		t.Errorf("after the revocation: %q", got)
	}
}
