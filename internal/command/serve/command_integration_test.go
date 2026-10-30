//go:build integration

package serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
)

// config writes testdata/server.yaml with the test's socket, key file,
// admin address and a fresh application version (DBOS recovers only its
// own version's workflows).
func testConfig(t *testing.T, socket, kek, admin string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.NewReplacer(`spiffe_workload_socket: "unix:///replaced/by/the/test"`, `spiffe_workload_socket: "`+socket+`"`,
		`local_kek_file: "/replaced/by/the/test"`, `local_kek_file: "`+kek+`"`,
		"admin_listener:\n    listen_address: \"127.0.0.1:0\"", "admin_listener:\n    listen_address: \""+admin+"\"",
		`application_version: "test"`, `application_version: "serve-`+uuid.NewV7().String()+`"`).Replace(string(data))
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestServe: ligo serve starts in the order of §8.2 against a fake SPIRE
// agent, built-in plugins and the local-kek sealer, serves the admin API
// over mTLS with its core identity, and drains when its context ends.
func TestServe(t *testing.T) {
	for _, role := range []string{"MIGRATOR", "APP", "READER", "DBOS"} {
		if os.Getenv("LIGO_TEST_PG_"+role+"_DSN") == "" {
			t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
		}
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("LIGO_TEST_PG_MIGRATOR_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), "update system_settings set maintenance_mode = false, maintenance_reason = null")
		_ = conn.Close(context.Background())
	})

	dir, err := os.MkdirTemp("", "ligo-serve") // short: unix socket paths are limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ca := spiffetest.NewCA(t, "prod.internal")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	agent := &spiffetest.Agent{Key: key, SVIDs: []*workload.X509SVID{ca.SVID(t, "spiffe://prod.internal/ns/sys/sa/ligo")},
		Bundles: map[string][]byte{"prod.internal": ca.Cert.Raw}}
	socket := agent.Serve(t, dir, "prod")
	kek := filepath.Join(dir, "kek")
	if err := os.WriteFile(kek, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	admin := l.Addr().String()
	_ = l.Close()

	cmd := &Serve{ConfigFile: testConfig(t, socket, kek, admin), InsecureDev: true, MaintenanceMode: true, insecureDB: os.Getenv("CI") != ""}
	running, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- cmd.run(running, slog.New(slog.DiscardHandler)) }()

	// vera, a viewer, presents her SVID and checks that ligo presents its own
	vera := ca.SVID(t, "spiffe://prod.internal/ops/vera")
	veraKey, err := x509.ParsePKCS8PrivateKey(vera.GetX509SvidKey())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{vera.GetX509Svid()}, PrivateKey: veraKey}},
		InsecureSkipVerify: true, // the server's SVID has a URI SAN, no name: VerifyPeerCertificate checks it
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return err
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://prod.internal/ns/sys/sa/ligo" {
				return errors.New("not ligo's core identity")
			}
			return nil
		}}}}
	var m struct {
		MaintenanceMode bool `json:"maintenanceMode"`
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := client.Get("https://" + admin + "/v1/admin/maintenance")
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&m)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("maintenance: %d (%v)", resp.StatusCode, err)
			}
			break
		}
		select {
		case err := <-done:
			t.Fatalf("serve stopped: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the admin listener did not come up: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !m.MaintenanceMode {
		t.Error("--maintenance did not turn maintenance mode on")
	}
	// SIGHUP reloads the certificate files and nothing else: ligo keeps serving
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if resp, err := client.Get("https://" + admin + "/v1/admin/maintenance"); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("after SIGHUP: %v", err)
	} else {
		_ = resp.Body.Close()
	}

	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("shutdown: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not shut down")
	}
	if _, err := client.Get("https://" + admin + "/v1/admin/maintenance"); err == nil {
		t.Error("the admin listener still serves after shutdown")
	}
}

// TestServeRefuses: startup stops at the first failing step.
func TestServeRefuses(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	if err := (&Serve{ConfigFile: "testdata/missing.yaml"}).run(ctx, log); err == nil {
		t.Error("a missing configuration")
	}
	path := testConfig(t, "unix:///nonexistent", "/nonexistent", "127.0.0.1:1")
	t.Setenv("LIGO_TEST_PG_DBOS_DSN", "")
	if err := (&Serve{ConfigFile: path, InsecureDev: true}).run(ctx, log); err == nil || !strings.Contains(err.Error(), "dbos_dsn_env") {
		t.Errorf("an unset DSN variable: %v", err)
	}
}
