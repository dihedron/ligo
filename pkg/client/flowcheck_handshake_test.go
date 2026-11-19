package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// pgServer answers an SSLRequest with S and then serves TLS with cert, as HandshakePostgreSQL does.
func pgServer(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				var req [8]byte
				if _, err := io.ReadFull(c, req[:]); err != nil || req != [8]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f} {
					return
				}
				_, _ = c.Write([]byte("S"))
				_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
			}()
		}
	}()
	return port(t, l.Addr().String())
}

// svidServer serves TLS with an X509-SVID that has a URI SAN and no DNS name.
func svidServer(t *testing.T) (p int, bundle *x509bundle.Bundle) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "spire CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse("spiffe://example.org/ns/sys/sa/ligo")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return port(t, l.Addr().String()), x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("example.org"), []*x509.Certificate{ca})
}

func tlsFlow(p int, name string) Flow {
	return Flow{Name: name, Protocol: "TCP", Destination: "127.0.0.1", Ports: single(p), TLS: true}
}

// FC-10: the mapping chooses the check of a TLS flow, and only of a TLS flow.
func TestHandshakeMapping(t *testing.T) {
	pg := tlsFlow(5432, "postgres")
	pg.ServerName = "db.example.org"
	api := tlsFlow(8443, "api")
	udp := Flow{Name: "u", Protocol: "UDP", Destination: "127.0.0.1", Ports: single(5432), TLS: true}
	plain := Flow{Name: "p", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(5432)}
	by := func(f Flow, _ int) Handshake {
		switch f.Name {
		case "postgres", "u", "p":
			return HandshakePostgreSQL
		case "api":
			return HandshakeSPIFFE
		}
		return ""
	}
	protocols := func(h HandshakeFunc) map[string]string {
		got := map[string]string{}
		choose := func(_ BindingFlows, f Flow, p int) Handshake {
			if h == nil {
				return ""
			}
			return h(f, p)
		}
		for _, it := range plan(one(pg)[0], choose) {
			got["postgres"] = it.res.Protocol
		}
		for _, f := range []Flow{api, udp, plain} {
			for _, it := range plan(one(f)[0], choose) {
				got[f.Name] = it.res.Protocol + "|" + string(it.res.Status)
			}
		}
		return got
	}
	if got := protocols(nil); got["postgres"] != "tls" || got["api"] != "|skipped" {
		t.Errorf("without a mapping: %v", got) // a bare IP with no server name cannot be verified as a name
	}
	got := protocols(by)
	if got["postgres"] != "postgresql" || got["api"] != "spire|" || got["u"] != "udp|" || got["p"] != "tcp|" {
		t.Errorf("with the mapping: %v", got)
	}
}

// FC-11: a HandshakePostgreSQL flow, which a plain TLS check reports unreachable.
func TestHandshakePostgreSQL(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	p := pgServer(t, srv.TLS.Certificates[0])
	flow := tlsFlow(p, "postgres")
	flow.ServerName = "example.com" // the httptest certificate names example.com and 127.0.0.1
	mapping := WithHandshake(func(Flow, int) Handshake { return HandshakePostgreSQL })

	if r := run(t, one(flow), WithRoots(pool))[0]; r.Status != Unreachable {
		t.Errorf("a plain TLS check of HandshakePostgreSQL: %+v", r)
	}
	r := run(t, one(flow), WithRoots(pool), mapping)[0]
	if r.Status != Reachable || r.Protocol != "postgresql" {
		t.Errorf("the postgresql check: %+v", r)
	}
	if r := run(t, one(flow), mapping)[0]; r.Status != Unreachable {
		t.Errorf("an untrusted certificate must not verify: %+v", r)
	}
}

// FC-12: an SVID has no DNS name, so only the HandshakeSPIFFE check can verify it.
func TestHandshakeSPIFFE(t *testing.T) {
	p, bundle := svidServer(t)
	flow := tlsFlow(p, "workload-api")
	mapping := WithHandshake(func(Flow, int) Handshake { return HandshakeSPIFFE })

	r := run(t, one(flow), mapping, WithSPIFFE(bundle))[0]
	if r.Status != Reachable || r.Protocol != "spire" {
		t.Fatalf("the spire check: %+v", r)
	}
	if r := run(t, one(flow), mapping)[0]; r.Status != Unreachable || !strings.Contains(r.Reason, "no trust bundle") {
		t.Errorf("without a trust bundle: %+v", r)
	}
	other := x509bundle.New(spiffeid.RequireTrustDomainFromString("example.org"))
	if r := run(t, one(flow), mapping, WithSPIFFE(other))[0]; r.Status != Unreachable {
		t.Errorf("an empty trust bundle: %+v", r)
	}
	flow.ServerName = "ligo.example.org"
	if r := run(t, one(flow), WithRoots(x509.NewCertPool()))[0]; r.Status != Unreachable {
		t.Errorf("a plain TLS check of an SVID: %+v", r)
	}
}
