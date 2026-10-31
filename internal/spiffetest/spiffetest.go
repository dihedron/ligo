// Package spiffetest is a fake SPIRE agent for tests: a Workload API on a
// unix socket serving SVIDs of a test CA.
package spiffetest

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
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

// Agent is a fake SPIRE agent: a Workload API serving fixed SVIDs and
// bundles on a unix socket.
type Agent struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	SVIDs   []*workload.X509SVID
	Bundles map[string][]byte // DER, by trust domain
	Key     *ecdsa.PrivateKey // signs JWT-SVIDs
}

func (a *Agent) FetchX509SVID(_ *workload.X509SVIDRequest, s grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := s.Send(&workload.X509SVIDResponse{Svids: a.SVIDs}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func (a *Agent) FetchX509Bundles(_ *workload.X509BundlesRequest, s grpc.ServerStreamingServer[workload.X509BundlesResponse]) error {
	if err := s.Send(&workload.X509BundlesResponse{Bundles: a.Bundles}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func (a *Agent) FetchJWTBundles(_ *workload.JWTBundlesRequest, s grpc.ServerStreamingServer[workload.JWTBundlesResponse]) error {
	jwks := map[string][]byte{}
	for td := range a.Bundles {
		jwks[td] = []byte(`{"keys":[]}`)
	}
	if err := s.Send(&workload.JWTBundlesResponse{Bundles: jwks}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

// FetchJWTSVID signs an ES256 JWT-SVID for the requested subject.
func (a *Agent) FetchJWTSVID(_ context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	enc := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "k"})
	claims, _ := json.Marshal(map[string]any{"sub": req.GetSpiffeId(), "aud": req.GetAudience(), "exp": time.Now().Add(time.Hour).Unix()})
	signed := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, a.Key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return &workload.JWTSVIDResponse{Svids: []*workload.JWTSVID{{SpiffeId: req.GetSpiffeId(), Svid: signed + "." + enc(sig)}}}, nil
}

// Serve starts a on a socket in dir and returns its address.
func (a *Agent) Serve(t *testing.T, dir, name string) string {
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

// CA issues the SVIDs of one trust domain.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA creates the CA of trust domain td.
func NewCA(t *testing.T, td string) *CA {
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
	return &CA{cert, key}
}

// SVID issues an X509-SVID for id.
func (c *CA) SVID(t *testing.T, id string) *workload.X509SVID {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	return &workload.X509SVID{SpiffeId: id, X509Svid: der, X509SvidKey: pk, Bundle: c.Cert.Raw}
}
