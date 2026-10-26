//go:build integration && lab

package sealing

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
	"uuid"
)

// labEnv reads a variable of "lab.sh env --on ligo1"; these tests run only
// on ligo1, with its SPIRE agents.
func labEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: run the lab tests with test/lab/lab.sh test --on ligo1", name)
	}
	return v
}

// labKEK is the Transit KEK of ligo on the lab's bao-prod, logging in with
// ligo's JWT-SVID from the prod agent (ADR-07, §8.1 vault_transit).
func labKEK(t *testing.T) *TransitKEK {
	t.Helper()
	pem, err := os.ReadFile(labEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("no certificate in the lab CA file")
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	kek, err := NewTransitKEK(TransitConfig{
		Address:     labEnv(t, "LIGO_TEST_BAO_PROD_ADDR"),
		AuthMount:   "jwt-spiffe",
		Role:        "ligo-sealer",
		JWTAudience: labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE"),
		Mount:       "transit",
		KeyName:     "ligo-interstage",
	}, WorkloadJWT{Addr: labEnv(t, "LIGO_TEST_SPIRE_PROD_SOCKET")}, client)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// TestLabTransit seals and unseals over the lab's real OpenBao Transit,
// logged in with a real JWT-SVID (ADR-07, AC-08's unseal path).
func TestLabTransit(t *testing.T) {
	ctx := context.Background()
	kek := labKEK(t)
	if err := kek.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	s := NewSealer(kek)
	sc := Context{BindingID: uuid.NewV7(), Revision: 1, Attempt: 1, Stage: StageIdentity}
	env, err := s.Seal(ctx, sc, []byte("lab secret"))
	if err != nil {
		t.Fatal(err)
	}
	if env.KEK != "vault-transit:ligo-interstage" || len(env.WrappedDEK) < 10 || env.WrappedDEK[:7] != "vault:v" {
		t.Errorf("envelope: %+v", env)
	}
	got, err := s.Unseal(ctx, sc, env)
	if err != nil || string(got) != "lab secret" {
		t.Errorf("Unseal = (%q, %v)", got, err)
	}
	// a second KEK (as after a restart, AC-08) opens the same envelope
	if got, err := NewSealer(labKEK(t)).Unseal(ctx, sc, env); err != nil || string(got) != "lab secret" {
		t.Errorf("Unseal with a new KEK = (%q, %v)", got, err)
	}
	sc.Attempt++
	if _, err := s.Unseal(ctx, sc, env); !errors.Is(err, ErrSealedSecretUnavailable) {
		t.Errorf("other attempt: %v", err)
	}
}

// TestLabWorkloadJWT fetches ligo's JWT-SVID from the prod agent.
func TestLabWorkloadJWT(t *testing.T) {
	jwt, err := WorkloadJWT{Addr: labEnv(t, "LIGO_TEST_SPIRE_PROD_SOCKET")}.FetchJWT(context.Background(), "lab-test")
	if err != nil || len(jwt) < 20 {
		t.Fatalf("FetchJWT = (%q, %v)", jwt, err)
	}
	if _, err := (WorkloadJWT{Addr: "unix:///nonexistent.sock"}).FetchJWT(context.Background(), "x"); err == nil {
		t.Error("a missing socket gave a JWT")
	}
}
