package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/config"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
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

// agent is a fake SPIRE agent: a Workload API serving fixed SVIDs and
// bundles on a unix socket.
type agent struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	svids   []*workload.X509SVID
	bundles map[string][]byte
	key     *ecdsa.PrivateKey
}

func (a *agent) FetchX509SVID(_ *workload.X509SVIDRequest, s grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := s.Send(&workload.X509SVIDResponse{Svids: a.svids}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func (a *agent) FetchX509Bundles(_ *workload.X509BundlesRequest, s grpc.ServerStreamingServer[workload.X509BundlesResponse]) error {
	if err := s.Send(&workload.X509BundlesResponse{Bundles: a.bundles}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func (a *agent) FetchJWTBundles(_ *workload.JWTBundlesRequest, s grpc.ServerStreamingServer[workload.JWTBundlesResponse]) error {
	jwks := map[string][]byte{}
	for td := range a.bundles {
		jwks[td] = []byte(`{"keys":[]}`)
	}
	if err := s.Send(&workload.JWTBundlesResponse{Bundles: jwks}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

// FetchJWTSVID signs an ES256 JWT-SVID for the requested subject.
func (a *agent) FetchJWTSVID(_ context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	enc := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "k"})
	claims, _ := json.Marshal(map[string]any{"sub": req.GetSpiffeId(), "aud": req.GetAudience(), "exp": time.Now().Add(time.Hour).Unix()})
	signed := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return &workload.JWTSVIDResponse{Svids: []*workload.JWTSVID{{SpiffeId: req.GetSpiffeId(), Svid: signed + "." + enc(sig)}}}, nil
}

// serve starts a on a socket in dir and returns its address.
func (a *agent) serve(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name+".sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(s, a)
	go func() { _ = s.Serve(l) }()
	t.Cleanup(s.Stop)
	return "unix://" + path
}

// ca issues the SVIDs of one trust domain.
type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, td string) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: td}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		URIs: []*url.URL{{Scheme: "spiffe", Host: td}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{cert, key}
}

func (c *ca) svid(t *testing.T, id string) *workload.X509SVID {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	return &workload.X509SVID{SpiffeId: id, X509Svid: der, X509SvidKey: pk, Bundle: c.cert.Raw}
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
	prod, test := newCA(t, "prod.internal"), newCA(t, "test.internal")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prodAgent := &agent{key: key, svids: []*workload.X509SVID{prod.svid(t, "spiffe://prod.internal/ns/sys/sa/ligo"), prod.svid(t, "spiffe://prod.internal/ns/other")},
		bundles: map[string][]byte{"prod.internal": prod.cert.Raw}}
	testAgent := &agent{key: key, svids: []*workload.X509SVID{test.svid(t, "spiffe://test.internal/ns/sys/sa/ligo")},
		bundles: map[string][]byte{"test.internal": test.cert.Raw}}
	for i := range cfg.Zones {
		switch cfg.Zones[i].Name {
		case "prod":
			cfg.Zones[i].SPIFFEWorkloadSocket = prodAgent.serve(t, dir, "prod")
		default:
			cfg.Zones[i].SPIFFEWorkloadSocket = testAgent.serve(t, dir, cfg.Zones[i].Name)
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
	for td, want := range map[string]*x509.Certificate{"prod.internal": prod.cert, "test.internal": test.cert} {
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
