package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// caFile writes a self-signed CA certificate, as sslrootcert needs a
// readable file.
func caFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRequireVerifyFull checks §4.1: every connection uses TLS with
// sslmode=verify-full, unless insecure connections are allowed (CI).
func TestRequireVerifyFull(t *testing.T) {
	ca := caFile(t)
	for dsn, ok := range map[string]bool{
		"postgres://u@db:5432/ligo?sslmode=verify-full&sslrootcert=/ca.crt":  true,
		"host=db user=u dbname=ligo sslmode=verify-full sslrootcert=/ca.crt": true,
		"postgres://u@db:5432/ligo?sslmode=verify-ca&sslrootcert=/ca.crt":    false,
		"postgres://u@db:5432/ligo?sslmode=require":                          false,
		"postgres://u@db:5432/ligo?sslmode=prefer":                           false,
		"postgres://u@db:5432/ligo":                                          false, // default: prefer
		"postgres://u@db:5432/ligo?sslmode=disable":                          false,
	} {
		dsn = strings.ReplaceAll(dsn, "/ca.crt", ca)
		_, err := poolConfig(dsn, statementTimeoutApp, false)
		if ok && err != nil {
			t.Errorf("%s: %v", dsn, err)
		}
		if !ok && !errors.Is(err, ErrInsecureConnection) {
			t.Errorf("%s: got %v, want ErrInsecureConnection", dsn, err)
		}
		if !ok {
			if _, err := poolConfig(dsn, statementTimeoutApp, true); err != nil {
				t.Errorf("%s with insecure allowed: %v", dsn, err)
			}
		}
	}
	if _, err := poolConfig("::not a dsn::", statementTimeoutApp, true); err == nil {
		t.Error("invalid DSN accepted")
	}
}

func TestStatementTimeout(t *testing.T) {
	cfg, err := poolConfig("postgres://u@db/ligo?sslmode=disable", statementTimeoutReader, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ConnConfig.RuntimeParams["statement_timeout"]; got != "500" {
		t.Errorf("statement_timeout = %q, want 500 (ms)", got)
	}
}
