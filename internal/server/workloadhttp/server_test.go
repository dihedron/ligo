package workloadhttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	audience = "spiffe://prod.lab/ns/sys/sa/ligo"
	worker   = "spiffe://prod.lab/ns/app/sa/worker"
)

// bundles is the composite source of the tests: prod.lab only.
type bundles struct {
	x509 *x509bundle.Set
	jwt  *jwtbundle.Set
}

func (b bundles) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return b.x509.GetX509BundleForTrustDomain(td)
}

func (b bundles) GetJWTBundleForTrustDomain(td spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	return b.jwt.GetJWTBundleForTrustDomain(td)
}

type env struct {
	srv  *httptest.Server
	ca   *spiffetest.CA
	key  *ecdsa.PrivateKey // signs prod.lab's JWT-SVIDs
	s    *Server
	test *spiffetest.CA // test.lab, not accepted
}

func setup(t *testing.T, modes ...string) *env {
	t.Helper()
	prod, test := spiffetest.NewCA(t, "prod.lab"), spiffetest.NewCA(t, "test.lab")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	td := spiffeid.RequireTrustDomainFromString("prod.lab")
	jb := jwtbundle.New(td)
	if err := jb.AddJWTAuthority("k", &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	testTD := spiffeid.RequireTrustDomainFromString("test.lab")
	b := bundles{x509: x509bundle.NewSet(x509bundle.FromX509Authorities(td, []*x509.Certificate{prod.Cert}),
		x509bundle.FromX509Authorities(testTD, []*x509.Certificate{test.Cert})), jwt: jwtbundle.NewSet(jb)}
	s := &Server{Bundles: b, Logger: slog.New(slog.DiscardHandler), Listener: config.WorkloadListener{AuthModes: modes,
		AcceptedTrustDomains: []string{"prod.lab"}, ExpectedJWTAudience: audience, MaxTokenTTL: 15 * time.Minute, ClockSkew: 30 * time.Second,
		RateLimit: config.WorkloadRateLimit{PerSVIDRPS: 0.001, Burst: 3}}}
	srv := httptest.NewUnstartedServer(s.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, Caller(r).String())
	})))
	serverCert := certificate(t, prod, "spiffe://prod.lab/ns/sys/sa/ligo")
	srv.TLS = s.TLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCert, nil })
	srv.EnableHTTP2 = true // gRPC shares the port
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &env{srv: srv, ca: prod, key: key, s: s, test: test}
}

func certificate(t *testing.T, ca *spiffetest.CA, id string) tls.Certificate {
	t.Helper()
	svid := ca.SVID(t, id)
	key, err := x509.ParsePKCS8PrivateKey(svid.X509SvidKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{svid.X509Svid}, PrivateKey: key}
}

// client trusts the server's CA, without checking its name, and presents
// cert if given.
func (v *env) client(cert ...tls.Certificate) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: cert} //nolint:gosec // the server's SPIFFE ID is not under test
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// token signs an ES256 JWT-SVID with claims.
func (v *env) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "k"})
	body, _ := json.Marshal(claims)
	signed := enc(header) + "." + enc(body)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, v.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + enc(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func claims(sub string, aud any, iat, exp time.Time) map[string]any {
	c := map[string]any{"sub": sub, "aud": aud, "exp": exp.Unix()}
	if !iat.IsZero() {
		c["iat"] = iat.Unix()
	}
	return c
}

// get returns the status and body of GET / with an optional bearer token.
func (v *env) get(t *testing.T, c *http.Client, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", v.srv.URL+"/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestAuthentication: X.509-SVIDs of accepted trust domains, a bearer token
// that must repeat the mTLS identity, and JWT-SVIDs per AC-16 (§7.1).
func TestAuthentication(t *testing.T) {
	v := setup(t, config.AuthX509SVID, config.AuthJWTSVID)
	v.s.Listener.RateLimit.Burst = 100
	now := time.Now()
	good := v.token(t, claims(worker, audience, now, now.Add(5*time.Minute)))
	for _, c := range []struct {
		name   string
		client *http.Client
		token  string
		code   int
		caller string
	}{
		{"no credentials", v.client(), "", 401, ""},
		{"X.509-SVID", v.client(certificate(t, v.ca, worker)), "", 200, worker},
		{"X.509-SVID with the same subject in a token", v.client(certificate(t, v.ca, worker)), good, 200, worker},
		{"X.509-SVID with another subject in a token", v.client(certificate(t, v.ca, "spiffe://prod.lab/ns/app/sa/other")), good, 401, ""},
		{"X.509-SVID with an invalid token", v.client(certificate(t, v.ca, worker)), "nope", 401, ""},
		// its CA is not among the server's acceptable CAs, so the client sends no certificate
		{"X.509-SVID of a trust domain not accepted", v.client(certificate(t, v.test, "spiffe://test.lab/ns/app/sa/worker")), "", 401, ""},
		{"JWT-SVID", v.client(), good, 200, worker},
		{"JWT-SVID with another audience too", v.client(), v.token(t, claims(worker, []string{"other", audience}, now, now.Add(time.Minute))), 200, worker},
		{"AC-16: JWT-SVID without iat", v.client(), v.token(t, claims(worker, audience, time.Time{}, now.Add(time.Minute))), 401, ""},
		{"AC-16: JWT-SVID with the wrong audience", v.client(), v.token(t, claims(worker, "other", now, now.Add(time.Minute))), 401, ""},
		{"AC-16: JWT-SVID living longer than max_token_ttl", v.client(), v.token(t, claims(worker, audience, now, now.Add(16*time.Minute))), 401, ""},
		{"JWT-SVID issued beyond the clock skew", v.client(), v.token(t, claims(worker, audience, now.Add(time.Minute), now.Add(2*time.Minute))), 401, ""},
		{"expired JWT-SVID", v.client(), v.token(t, claims(worker, audience, now.Add(-2*time.Minute), now.Add(-time.Minute))), 401, ""},
		{"JWT-SVID of a trust domain not accepted", v.client(), v.token(t, claims("spiffe://test.lab/ns/app/sa/worker", audience, now, now.Add(time.Minute))), 401, ""},
	} {
		code, body := v.get(t, c.client, c.token)
		if code != c.code || (c.caller != "" && body != c.caller) {
			t.Errorf("%s: %d %q, want %d %q", c.name, code, body, c.code, c.caller)
		}
	}
}

// TestAuthModes: a mode left out of auth_modes is not accepted.
func TestAuthModes(t *testing.T) {
	now := time.Now()
	jwtOnly := setup(t, config.AuthJWTSVID)
	if code, _ := jwtOnly.get(t, jwtOnly.client(certificate(t, jwtOnly.ca, worker)), ""); code != 401 {
		t.Errorf("X.509-SVID with jwt_svid only: %d", code)
	}
	x509Only := setup(t, config.AuthX509SVID)
	if code, _ := x509Only.get(t, x509Only.client(), x509Only.token(t, claims(worker, audience, now, now.Add(time.Minute)))); code != 401 {
		t.Errorf("JWT-SVID with x509_svid only: %d", code)
	}
}

// TestRateLimit: each SPIFFE ID has its own bucket; beyond it, 429.
func TestRateLimit(t *testing.T) {
	v := setup(t, config.AuthX509SVID)
	c := v.client(certificate(t, v.ca, worker))
	var codes []int
	for range 4 {
		code, _ := v.get(t, c, "")
		codes = append(codes, code)
	}
	if fmt.Sprint(codes) != "[200 200 200 429]" {
		t.Errorf("worker: %v", codes)
	}
	if code, _ := v.get(t, v.client(certificate(t, v.ca, "spiffe://prod.lab/ns/app/sa/other")), ""); code != 200 {
		t.Errorf("another caller: %d", code)
	}
}
