package serve

import (
	"bytes"
	"context"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/dihedron/ligo/internal/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"net/http"
	"net/http/httptest"
)

// TestConfigValid: the integration test's configuration passes the static
// checks of §8.2 (with --insecure-dev, for local-kek).
func TestConfigValid(t *testing.T) {
	data, err := os.ReadFile("testdata/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(cfg, config.Options{InsecureDev: true, LookupEnv: func(string) (string, bool) { return "x", true }}); err != nil {
		t.Fatal(err)
	}
}

// TestCertificate: the admin certificate comes from the configured files
// and is reloaded from them (SIGHUP); a pair that fails to load keeps the
// old one.
func TestCertificate(t *testing.T) {
	dir := t.TempDir()
	ca := spiffetest.NewCA(t, "prod.internal")
	certFile, keyFile := filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
	write := func(id string) []byte {
		svid := ca.SVID(t, id)
		_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svid.GetX509Svid()}), 0o600)
		_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: svid.GetX509SvidKey()}), 0o600)
		return svid.GetX509Svid()
	}
	first := write("spiffe://prod.internal/ns/sys/sa/ligo")
	get, reload, err := certificate("admin_listener", "file", certFile, keyFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := get(nil); err != nil || !bytes.Equal(c.Certificate[0], first) {
		t.Errorf("file certificate: %v", err)
	}
	renewed := write("spiffe://prod.internal/ns/sys/sa/ligo")
	log := slog.New(slog.DiscardHandler)
	reloadAll(log, reload)
	if c, _ := get(nil); !bytes.Equal(c.Certificate[0], renewed) {
		t.Error("the renewed certificate was not reloaded")
	}
	_ = os.WriteFile(keyFile, []byte("broken"), 0o600)
	if err := reload(); err == nil {
		t.Error("a broken key file reloaded")
	}
	if c, _ := get(nil); !bytes.Equal(c.Certificate[0], renewed) {
		t.Error("a failed reload replaced the certificate")
	}
	if _, _, err := certificate("admin_listener", "file", filepath.Join(dir, "none"), "", nil); err == nil {
		t.Error("a missing certificate file")
	}
	if _, reload, err := certificate("admin_listener", "spiffe", "", "", nil); err != nil || reload != nil {
		t.Errorf("SPIRE rotates its own certificate: %v", err)
	}
}

// reloadAll is SIGHUP with only a certificate to reload.
func reloadAll(log *slog.Logger, reloadCert func() error) {
	reload(log, &config.Config{}, map[string]func() error{"admin": reloadCert}, nil)
}

// TestLDAP: the directory reads its bind password from the environment,
// its CA from a file, and knows the groups of the authorization bindings.
func TestLDAP(t *testing.T) {
	dir := t.TempDir()
	ca := spiffetest.NewCA(t, "ldap")
	caFile := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o600)
	cfg := &config.Config{AdminAuth: config.AdminAuth{LDAP: config.LDAP{ServiceBindPasswordEnv: "LIGO_TEST_LDAP_PW", CACertFile: caFile}},
		Authorization: config.Authorization{Bindings: []config.RoleBinding{{LDAPGroupDN: "cn=a"}, {SPIFFEID: "spiffe://x/y"}, {LDAPGroupDN: "cn=b"}, {LDAPGroupDN: "cn=a"}}}} // cn=a twice: searched once
	if _, err := ldap(cfg); err == nil {
		t.Error("an unset bind password variable")
	}
	t.Setenv("LIGO_TEST_LDAP_PW", "pw")
	d, err := ldap(cfg)
	if err != nil || d.BindPassword != "pw" || d.RootCAs == nil || len(d.Groups) != 2 {
		t.Errorf("directory: %+v (%v)", d, err)
	}
	// SIGHUP reloads a renewed CA file; a broken one keeps the old CAs
	renewed := spiffetest.NewCA(t, "ldap-renewed")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: renewed.Cert.Raw}), 0o600)
	before := d.RootCAs
	reload(slog.New(slog.DiscardHandler), cfg, nil, d)
	if d.RootCAs == before {
		t.Error("the renewed CA file was not reloaded")
	}
	reloaded := d.RootCAs
	_ = os.WriteFile(caFile, []byte("broken"), 0o600)
	reload(slog.New(slog.DiscardHandler), cfg, nil, d)
	if d.RootCAs != reloaded {
		t.Error("a broken CA file replaced the CAs")
	}
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: renewed.Cert.Raw}), 0o600)

	cfg.AdminAuth.LDAP.CACertFile = filepath.Join(dir, "none")
	if _, err := ldap(cfg); err == nil {
		t.Error("a missing CA file")
	}
	_ = os.WriteFile(caFile, []byte("not a certificate"), 0o600)
	cfg.AdminAuth.LDAP.CACertFile = caFile
	if _, err := ldap(cfg); err == nil {
		t.Error("a CA file without certificates")
	}
}

// TestSealer: local-kek needs --insecure-dev; unknown providers are refused.
func TestSealer(t *testing.T) {
	ctx := context.Background()
	kek := filepath.Join(t.TempDir(), "kek")
	_ = os.WriteFile(kek, make([]byte, 32), 0o600)
	cfg := &config.Config{SecretSealing: config.SecretSealing{Provider: "local-kek", LocalKEKFile: kek}}
	if _, _, err := (&Serve{}).sealer(ctx, cfg, nil); err == nil {
		t.Error("local-kek without --insecure-dev")
	}
	if s, signer, err := (&Serve{InsecureDev: true}).sealer(ctx, cfg, nil); err != nil || s == nil || signer == nil {
		t.Errorf("local-kek: %v", err)
	}
	cfg.SecretSealing.Provider = "rot13"
	if _, _, err := (&Serve{InsecureDev: true}).sealer(ctx, cfg, nil); err == nil {
		t.Error("an unknown provider")
	}
}

// TestExecute: a failed startup is reported as the command's error.
func TestExecute(t *testing.T) {
	if err := (&Serve{ConfigFile: filepath.Join(t.TempDir(), "missing.yaml")}).Execute(nil); err == nil {
		t.Error("a missing configuration")
	}
}

// TestTraced: an HTTP request gets a span named after the listener and
// the method, continuing the caller's trace (traceparent); a gRPC request
// gets none here, as the gRPC server makes its own.
func TestTraced(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	before := otel.GetTracerProvider()
	otel.SetTracerProvider(tracing.Provider(rec, 1, "test", "a"))
	t.Cleanup(func() { otel.SetTracerProvider(before) })
	if _, err := tracing.Setup(context.Background(), config.Tracing{}, "", ""); err != nil { // the propagator
		t.Fatal(err)
	}
	h := traced("admin", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	const parent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	r := httptest.NewRequest("GET", "/v1/admin/maintenance", nil)
	r.Header.Set("traceparent", parent)
	h.ServeHTTP(httptest.NewRecorder(), r)
	g := httptest.NewRequest("POST", "/ligo.workload.v1alpha1.WorkloadBindingService/ListBindings", nil)
	g.Header.Set("Content-Type", "application/grpc")
	h.ServeHTTP(httptest.NewRecorder(), g)
	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("%d spans, want 1", len(ended))
	}
	if s := ended[0]; s.Name() != "admin GET" || s.SpanContext().TraceID().String() != "0af7651916cd43dd8448eb211c80319c" ||
		s.Parent().SpanID().String() != "b7ad6b7169203331" {
		t.Errorf("span %s trace %s parent %s", s.Name(), s.SpanContext().TraceID(), s.Parent().SpanID())
	}
}
