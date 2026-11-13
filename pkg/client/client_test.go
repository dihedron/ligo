package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	ligoID   = "spiffe://prod.lab/ns/sys/sa/ligo"
	workerID = "spiffe://prod.lab/ns/app/sa/worker"
)

// source is a fixed SVID with its trust domain's bundle.
type source struct {
	*x509svid.SVID
	*x509bundle.Bundle
}

type env struct {
	ca     *spiffetest.CA
	bundle *x509bundle.Bundle
	source source
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ca := spiffetest.NewCA(t, "prod.lab")
	v := &env{ca: ca, bundle: x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("prod.lab"), []*x509.Certificate{ca.Cert})}
	v.source = source{v.svid(t, workerID), v.bundle}
	return v
}

func (v *env) svid(t *testing.T, id string) *x509svid.SVID {
	t.Helper()
	w := v.ca.SVID(t, id)
	s, err := x509svid.ParseRaw(w.GetX509Svid(), w.GetX509SvidKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// serve starts a TLS server that presents id and requires a client SVID of
// the trust domain; it returns its host:port.
func (v *env) serve(t *testing.T, id string, h http.Handler) string {
	t.Helper()
	s := v.svid(t, id)
	cfg := tlsconfig.MTLSServerConfig(s, v.bundle, tlsconfig.AuthorizeMemberOf(spiffeid.RequireTrustDomainFromString("prod.lab")))
	cert, err := tlsconfig.GetCertificate(s)(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates, cfg.GetCertificate = []tls.Certificate{*cert}, nil // httptest would add its own certificate otherwise
	srv := httptest.NewUnstartedServer(h)
	srv.TLS, srv.EnableHTTP2 = cfg, true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func (v *env) client(t *testing.T, address string, transport ...Transport) *Client {
	t.Helper()
	c, err := New(t.Context(), Config{Address: address, ServerID: ligoID, X509Source: v.source, Transport: append(transport, REST)[0]})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

const bindingsBody = `{"callerSpiffeId":"` + workerID + `","items":[{"id":"0192","name":"workers-ledger","source":"workers","target":"ledger",
	"accessLevel":"write","platformType":"postgres","platform":"pg-prod","revision":4,"updatedAt":"2026-10-16T07:02:11Z",
	"auth":{"secretStorageStrategy":"vault-static","secretStoreType":"vault","secretStoreInstance":"vault-prod",
		"config":{"address":"https://vault.lab:8200","audience":"https://vault.lab","authMount":"jwt","role":"binding-0192","policy":"binding-0192","secretPath":"kv/data/bindings/0192"}},
	"spec":{"endpoint":"db.lab:5432","database":"ledger","port":5432}}]}`

// TestNewValidates is CS-1 for the fields this chunk has.
func TestNewValidates(t *testing.T) {
	v := newEnv(t)
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"no address":        {Config{ServerID: ligoID}, "Address"},
		"address with URL":  {Config{Address: "https://ligo.lab", ServerID: ligoID}, "Address"},
		"no server ID":      {Config{Address: "ligo.lab:8443"}, "ServerID"},
		"bad server ID":     {Config{Address: "ligo.lab:8443", ServerID: "ligo"}, "ServerID"},
		"unknown transport": {Config{Address: "ligo.lab:8443", ServerID: ligoID, Transport: "soap"}, "Transport"},
	} {
		tc.cfg.X509Source = v.source
		if _, err := New(t.Context(), tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestBindings is CS-2 and CS-3: the items decoded, the filters sent, an
// empty list, and the remembered list on 304.
func TestBindings(t *testing.T) {
	v := newEnv(t)
	var queries, etags []string
	body := bindingsBody
	c := v.client(t, v.serve(t, ligoID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries, etags = append(queries, r.URL.Path+"?"+r.URL.RawQuery), append(etags, r.Header.Get("If-None-Match"))
		w.Header().Set("ETag", `"sha256:1"`)
		if r.Header.Get("If-None-Match") == `"sha256:1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(body))
	})))
	f := Filter{Target: "ledger", PlatformType: "postgres"}
	got, err := c.Bindings(t.Context(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := []Binding{{ID: "0192", Name: "workers-ledger", Source: "workers", Target: "ledger", AccessLevel: "write", PlatformType: "postgres",
		Platform: "pg-prod", Revision: 4, UpdatedAt: time.Date(2026, 10, 16, 7, 2, 11, 0, time.UTC),
		Spec: map[string]any{"endpoint": "db.lab:5432", "database": "ledger", "port": float64(5432)},
		Auth: Auth{Strategy: "vault-static", StoreType: "vault", StoreInstance: "vault-prod", Config: map[string]string{"address": "https://vault.lab:8200",
			"audience": "https://vault.lab", "authMount": "jwt", "role": "binding-0192", "policy": "binding-0192", "secretPath": "kv/data/bindings/0192"}}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bindings\n got %+v\nwant %+v", got, want)
	}
	if got[0].Endpoint() != "db.lab:5432" || (Binding{}).Endpoint() != "" {
		t.Error("Endpoint")
	}
	again, err := c.Bindings(t.Context(), f)
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Errorf("after 304: %+v (%v)", again, err)
	}
	body = `{"items":[]}`
	none, err := c.Bindings(t.Context(), Filter{})
	if err != nil || none == nil || len(none) != 0 {
		t.Errorf("no binding: %v (%v)", none, err)
	}
	if want := []string{"/v1/bindings?platformType=postgres&target=ledger", "/v1/bindings?platformType=postgres&target=ledger", "/v1/bindings?"}; !reflect.DeepEqual(queries, want) {
		t.Errorf("queries %q", queries)
	}
	if want := []string{"", `"sha256:1"`, ""}; !reflect.DeepEqual(etags, want) { // the ETag is remembered per filter
		t.Errorf("etags %q", etags)
	}
}

func TestFlows(t *testing.T) {
	v := newEnv(t)
	var query string
	c := v.client(t, v.serve(t, ligoID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Path + "?" + r.URL.RawQuery
		_, _ = w.Write([]byte(`{"items":[{"binding":"workers-ledger","source":"workers","target":"ledger","flows":[
			{"name":"db","purpose":"DATA","protocol":"TCP","destination":"db.lab","ports":[5432,"6000-6010"],"tls":true,"serverName":"db.lab","description":"d","declaredBy":"target:ledger"}]}]}`))
	})))
	got, err := c.Flows(t.Context(), Filter{Target: "ledger", PlatformType: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	want := []BindingFlows{{Binding: "workers-ledger", Source: "workers", Target: "ledger", Flows: []Flow{{Name: "db", Purpose: "DATA", Protocol: "TCP",
		Destination: "db.lab", Ports: []PortRange{{5432, 5432}, {6000, 6010}}, TLS: true, ServerName: "db.lab", Description: "d", DeclaredBy: "target:ledger"}}}}
	if !reflect.DeepEqual(got, want) || query != "/v1/flows?target=ledger" {
		t.Errorf("flows %+v, query %q", got, query)
	}
	for _, bad := range []string{`true`, `"a-b"`, `"80"`} {
		if err := json.Unmarshal([]byte(bad), new(PortRange)); err == nil {
			t.Errorf("port %s accepted", bad)
		}
	}
}

// TestRefusals is CS-4 and CS-13.
func TestRefusals(t *testing.T) {
	v := newEnv(t)
	status := func(code int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
	}
	closed := v.serve(t, ligoID, status(200))
	for name, tc := range map[string]struct {
		address string
		is      error
		text    string
	}{
		"another SPIFFE ID": {v.serve(t, "spiffe://prod.lab/ns/sys/sa/other", status(200)), ErrUnauthorized, "unexpected ID"},
		"401":               {v.serve(t, ligoID, status(401)), ErrUnauthorized, "401"},
		"403":               {v.serve(t, ligoID, status(403)), ErrUnauthorized, "403"},
		"503":               {v.serve(t, ligoID, status(503)), ErrUnavailable, "503"},
		"429":               {v.serve(t, ligoID, status(429)), ErrUnavailable, "429"},
		"500":               {v.serve(t, ligoID, status(500)), nil, "500"},
		"not JSON":          {v.serve(t, ligoID, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) })), nil, "not a bindings document"},
		"too large": {v.serve(t, ligoID, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"items":[],"pad":"` + strings.Repeat("x", maxBody) + `"}`))
		})), nil, "larger than"},
		"nobody listens": {"127.0.0.1:1", ErrUnavailable, "connect"},
	} {
		c := v.client(t, tc.address)
		_, err := c.Bindings(t.Context(), Filter{})
		if err == nil || !strings.Contains(err.Error(), tc.text) || tc.is != nil && !errors.Is(err, tc.is) {
			t.Errorf("%s: %v", name, err)
		}
		if tc.is == nil && (errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrUnavailable)) {
			t.Errorf("%s: %v has a sentinel", name, err)
		}
		if _, err := c.Flows(t.Context(), Filter{}); err == nil {
			t.Errorf("%s: flows answered", name)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := v.client(t, closed).Bindings(ctx, Filter{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// TestTLSConfig: the configuration for a target accepts only the named
// server and never TLS 1.2.
func TestTLSConfig(t *testing.T) {
	v := newEnv(t)
	c := v.client(t, "ligo.lab:8443")
	target := "spiffe://prod.lab/ns/lab/sa/db"
	addr := v.serve(t, target, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dial := func(id string) error {
		cfg := c.TLSConfig(spiffeid.RequireFromString(id))
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion %x", cfg.MinVersion)
		}
		conn, err := tls.Dial("tcp", addr, cfg)
		if err == nil {
			_ = conn.Close()
		}
		return err
	}
	if err := dial(target); err != nil {
		t.Errorf("the target: %v", err)
	}
	if err := dial(ligoID); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("another server: %v", err)
	}
}

// TestDefaultSource: with no X509Source the client takes its SVID from the
// Workload API at SPIFFE_ENDPOINT_SOCKET and closes that source.
func TestDefaultSource(t *testing.T) {
	v := newEnv(t)
	agent := &spiffetest.Agent{SVIDs: []*workload.X509SVID{v.ca.SVID(t, workerID)}, Bundles: map[string][]byte{"prod.lab": v.ca.Cert.Raw}}
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", agent.Serve(t, t.TempDir(), "agent.sock"))
	var caller string
	address := v.serve(t, ligoID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller = r.TLS.PeerCertificates[0].URIs[0].String()
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	c, err := New(t.Context(), Config{Address: address, ServerID: ligoID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Bindings(t.Context(), Filter{}); err != nil || caller != workerID {
		t.Errorf("caller %q (%v)", caller, err)
	}
	if err := c.Close(); err != nil {
		t.Error(err)
	}
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	if _, err := New(t.Context(), Config{Address: address, ServerID: ligoID}); err == nil || !strings.Contains(err.Error(), "Workload API") {
		t.Errorf("no socket: %v", err)
	}
}
