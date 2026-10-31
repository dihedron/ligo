package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// zoneBundles is a zone's bundle stream for the test: its bundle sets.
type zoneBundles struct {
	x509 *x509bundle.Set
	jwt  *jwtbundle.Set
}

func (b zoneBundles) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return b.x509.GetX509BundleForTrustDomain(td)
}

func (b zoneBundles) GetJWTBundleForTrustDomain(td spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	return b.jwt.GetJWTBundleForTrustDomain(td)
}

// TestRoute: each trust domain is verified only with the bundles of its
// authoritative zone, a federated one with those of its via_zone; a bundle
// another zone happens to carry is never used (§7.1).
func TestRoute(t *testing.T) {
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	td := spiffeid.RequireTrustDomainFromString
	cert := func(cn string) *x509.Certificate { return &x509.Certificate{Raw: []byte(cn)} }
	prodCA, cloudCA, rogueCA := cert("prod"), cert("cloud"), cert("rogue")
	byZone := map[string]bundles{
		"prod": zoneBundles{x509bundle.NewSet(x509bundle.FromX509Authorities(td("prod.internal"), []*x509.Certificate{prodCA}),
			x509bundle.FromX509Authorities(td("cloud.internal"), []*x509.Certificate{cloudCA})), jwtbundle.NewSet()},
		// the test zone's agent also carries a cloud.internal bundle, which is not authoritative
		"test": zoneBundles{x509bundle.NewSet(x509bundle.FromX509Authorities(td("cloud.internal"), []*x509.Certificate{rogueCA})), jwtbundle.NewSet()},
	}
	z := &Zones{authority: map[spiffeid.TrustDomain]bundles{}}
	if err := z.route(cfg, func(name string) bundles { return byZone[name] }); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]*x509.Certificate{"prod.internal": prodCA, "cloud.internal": cloudCA} {
		b, err := z.GetX509BundleForTrustDomain(td(name))
		if err != nil || !b.HasX509Authority(want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if b, err := z.GetX509BundleForTrustDomain(td("test.internal")); err == nil {
		t.Errorf("test.internal has no bundle in its zone, got %v", b)
	}
	if _, err := z.GetX509BundleForTrustDomain(td("evil.example")); err == nil {
		t.Error("a trust domain no zone is authoritative for")
	}
	if _, err := z.GetJWTBundleForTrustDomain(td("evil.example")); err == nil {
		t.Error("JWT: a trust domain no zone is authoritative for")
	}
}

// TestOpen: ligo connects to every zone's agent, takes the core identity
// its selector picks in the core zone, verifies with each zone's bundles,
// and fetches JWT-SVIDs as the core identity.
func TestOpen(t *testing.T) {
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "ligo-identity") // short: unix socket paths are limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	prod, test := spiffetest.NewCA(t, "prod.internal"), spiffetest.NewCA(t, "test.internal")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prodAgent := &spiffetest.Agent{Key: key, SVIDs: []*workload.X509SVID{prod.SVID(t, "spiffe://prod.internal/ns/sys/sa/ligo"), prod.SVID(t, "spiffe://prod.internal/ns/other")},
		Bundles: map[string][]byte{"prod.internal": prod.Cert.Raw}}
	testAgent := &spiffetest.Agent{Key: key, SVIDs: []*workload.X509SVID{test.SVID(t, "spiffe://test.internal/ns/sys/sa/ligo")},
		Bundles: map[string][]byte{"test.internal": test.Cert.Raw}}
	for i := range cfg.Zones {
		switch cfg.Zones[i].Name {
		case "prod":
			cfg.Zones[i].SPIFFEWorkloadSocket = prodAgent.Serve(t, dir, "prod")
		default:
			cfg.Zones[i].SPIFFEWorkloadSocket = testAgent.Serve(t, dir, cfg.Zones[i].Name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	z, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	svid, err := z.GetX509SVID()
	if err != nil || svid.ID.String() != "spiffe://prod.internal/ns/sys/sa/ligo" {
		t.Errorf("core identity: %v (%v)", svid, err)
	}
	for td, want := range map[string]*x509.Certificate{"prod.internal": prod.Cert, "test.internal": test.Cert} {
		if b, err := z.GetX509BundleForTrustDomain(spiffeid.RequireTrustDomainFromString(td)); err != nil || !b.HasX509Authority(want) {
			t.Errorf("bundle of %s: %v", td, err)
		}
	}
	jwt, err := z.FetchJWT(ctx, "https://vault.prod.internal")
	if err != nil || !strings.Contains(jwt, ".") {
		t.Errorf("JWT-SVID: %q (%v)", jwt, err)
	}
	if err := z.Close(); err != nil {
		t.Errorf("close: %v", err)
	}

	// a selector matching two SVIDs of the core zone is refused
	cfg.CoreIdentity.SVIDSelector.MatchExpr = `trust_domain == "prod.internal"`
	if _, err := Open(ctx, cfg); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Errorf("ambiguous core identity: %v", err)
	}
}
