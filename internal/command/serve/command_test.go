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
	get, reload, err := certificate(config.AdminListener{TLSSource: "file", TLSCertFile: certFile, TLSKeyFile: keyFile}, nil)
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
	if _, _, err := certificate(config.AdminListener{TLSSource: "file", TLSCertFile: filepath.Join(dir, "none")}, nil); err == nil {
		t.Error("a missing certificate file")
	}
	if _, reload, err := certificate(config.AdminListener{TLSSource: "spiffe"}, nil); err != nil || reload != nil {
		t.Errorf("SPIRE rotates its own certificate: %v", err)
	}
}

// reloadAll is SIGHUP with only a certificate to reload.
func reloadAll(log *slog.Logger, reloadCert func() error) {
	reload(log, &config.Config{}, reloadCert, nil)
}

// TestLDAP: the directory reads its bind password from the environment,
// its CA from a file, and knows the groups of the authorization bindings.
func TestLDAP(t *testing.T) {
	dir := t.TempDir()
	ca := spiffetest.NewCA(t, "ldap")
	caFile := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o600)
	cfg := &config.Config{AdminAuth: config.AdminAuth{LDAP: config.LDAP{ServiceBindPasswordEnv: "LIGO_TEST_LDAP_PW", CACertFile: caFile}},
		Authorization: config.Authorization{Bindings: []config.RoleBinding{{LDAPGroupDN: "cn=a"}, {SPIFFEID: "spiffe://x/y"}, {LDAPGroupDN: "cn=b"}}}}
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
	if _, err := (&Serve{}).sealer(ctx, cfg, nil); err == nil {
		t.Error("local-kek without --insecure-dev")
	}
	if s, err := (&Serve{InsecureDev: true}).sealer(ctx, cfg, nil); err != nil || s == nil {
		t.Errorf("local-kek: %v", err)
	}
	cfg.SecretSealing.Provider = "rot13"
	if _, err := (&Serve{InsecureDev: true}).sealer(ctx, cfg, nil); err == nil {
		t.Error("an unknown provider")
	}
}

// TestExecute: a failed startup is reported as the command's error.
func TestExecute(t *testing.T) {
	if err := (&Serve{ConfigFile: filepath.Join(t.TempDir(), "missing.yaml")}).Execute(nil); err == nil {
		t.Error("a missing configuration")
	}
}
