package adminclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	ligoID   = "spiffe://prod.lab/ns/sys/sa/ligo"
	otherID  = "spiffe://prod.lab/ns/app/sa/other"
	workerID = "spiffe://prod.lab/ns/app/sa/worker"
)

// source is a fixed SVID with its trust domain's bundle.
type source struct {
	*x509svid.SVID
	*x509bundle.Bundle
}

type env struct {
	ca     *spiffetest.CA
	bundle *x509bundle.Bundle
	source source
}

func newEnv(t testing.TB) *env {
	t.Helper()
	ca := spiffetest.NewCA(t, "prod.lab")
	v := &env{ca: ca, bundle: x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("prod.lab"), []*x509.Certificate{ca.Cert})}
	v.source = source{v.svid(t, workerID), v.bundle}
	return v
}

func (v *env) svid(t testing.TB, id string) *x509svid.SVID {
	t.Helper()
	w := v.ca.SVID(t, id)
	s, err := x509svid.ParseRaw(w.GetX509Svid(), w.GetX509SvidKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// serveSPIFFE starts a TLS server that presents id and requires a client
// SVID of the trust domain; it returns its URL.
func (v *env) serveSPIFFE(t testing.TB, id string, h http.Handler) string {
	t.Helper()
	s := v.svid(t, id)
	cfg := tlsconfig.MTLSServerConfig(s, v.bundle, tlsconfig.AuthorizeMemberOf(spiffeid.RequireTrustDomainFromString("prod.lab")))
	cert, err := tlsconfig.GetCertificate(s)(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates, cfg.GetCertificate = []tls.Certificate{*cert}, nil // httptest would add its own certificate otherwise
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// serveTLS starts an ordinary HTTPS server; it returns its URL and the
// pool that verifies it.
func serveTLS(t testing.TB, h http.Handler) (string, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

func problem(w http.ResponseWriter, code int, slug, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"type":"urn:ligo:problem:%s","title":%q,"status":%d,"detail":%q}`, slug, http.StatusText(code), code, detail)
}

// ping is the one call this chunk can make: GET /v1/admin/maintenance.
func ping(c *Client) error {
	var out map[string]any
	return c.exec(context.Background(), c.gen.GetMaintenance, &out)
}

// TestNewValidates is AC-1.
func TestNewValidates(t *testing.T) {
	v := newEnv(t)
	pool := x509.NewCertPool()
	basic := &BasicAuth{Username: "ada", Password: "s3cret"}
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"no URL":                   {Config{RootCAs: pool, Basic: basic}, "ServerURL"},
		"http":                     {Config{ServerURL: "http://ligo.lab:9443", RootCAs: pool, Basic: basic}, "https"},
		"no scheme":                {Config{ServerURL: "ligo.lab:9443", RootCAs: pool, Basic: basic}, "https"},
		"credentials in the URL":   {Config{ServerURL: "https://ada:x@ligo.lab:9443", RootCAs: pool, Basic: basic}, "ServerURL"},
		"a query in the URL":       {Config{ServerURL: "https://ligo.lab:9443/?a=b", RootCAs: pool, Basic: basic}, "ServerURL"},
		"no verification":          {Config{ServerURL: "https://ligo.lab:9443", Basic: basic}, "verif"},
		"an ID without a bundle":   {Config{ServerURL: "https://ligo.lab:9443", ServerID: ligoID, Basic: basic}, "Bundles"},
		"a bundle without an ID":   {Config{ServerURL: "https://ligo.lab:9443", Bundles: v.bundle, Basic: basic}, "ServerID"},
		"a bad ID":                 {Config{ServerURL: "https://ligo.lab:9443", ServerID: "ligo", Bundles: v.bundle, Basic: basic}, "ServerID"},
		"no authentication":        {Config{ServerURL: "https://ligo.lab:9443", RootCAs: pool}, "authentication"},
		"both authentications":     {Config{ServerURL: "https://ligo.lab:9443", RootCAs: pool, Basic: basic, X509Source: v.source}, "authentication"},
		"basic without a user":     {Config{ServerURL: "https://ligo.lab:9443", RootCAs: pool, Basic: &BasicAuth{Password: "x"}}, "Username"},
		"basic without a password": {Config{ServerURL: "https://ligo.lab:9443", RootCAs: pool, Basic: &BasicAuth{Username: "ada"}}, "Password"},
		"a custom round tripper":   {Config{ServerURL: "https://ligo.lab:9443", RootCAs: pool, Basic: basic, HTTPClient: &http.Client{Transport: roundTripper{}}}, "HTTPClient"},
		"a retry count below -1":   {Config{ServerURL: "https://ligo.lab:9443", RootCAs: pool, Basic: basic, MaxRetries: -2}, "MaxRetries"},
	} {
		c, err := New(tc.cfg)
		if err == nil {
			_ = c.Close()
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want it to mention %q", name, err, tc.want)
		}
	}
	for name, cfg := range map[string]Config{
		"basic, roots":      {ServerURL: "https://ligo.lab:9443", RootCAs: pool, Basic: basic},
		"basic, SPIFFE ID":  {ServerURL: "https://ligo.lab:9443", ServerID: ligoID, Bundles: v.bundle, Basic: basic},
		"SVID, SPIFFE ID":   {ServerURL: "https://ligo.lab:9443", ServerID: ligoID, X509Source: v.source},
		"SVID, roots":       {ServerURL: "https://ligo.lab:9443", RootCAs: pool, X509Source: v.source},
		"a path in the URL": {ServerURL: "https://ligo.lab/ligo/", RootCAs: pool, Basic: basic},
	} {
		c, err := New(cfg)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		_ = c.Close()
	}
}

type roundTripper struct{}

func (roundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, errors.New("no") }

// TestServerVerification is AC-2: another SPIFFE ID, a certificate outside
// the roots, and a redirect are all refused, and the password goes nowhere.
func TestServerVerification(t *testing.T) {
	v := newEnv(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })

	// the right SPIFFE ID, over mTLS
	url := v.serveSPIFFE(t, ligoID, ok)
	c, err := New(Config{ServerURL: url, ServerID: ligoID, X509Source: v.source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := ping(c); err != nil {
		t.Errorf("the right server: %v", err)
	}

	// another SPIFFE ID
	var seen atomic.Int32
	other := v.serveSPIFFE(t, otherID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen.Add(1) }))
	c2, err := New(Config{ServerURL: other, ServerID: ligoID, Bundles: v.bundle, Basic: &BasicAuth{Username: "ada", Password: "s3cret"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	if err := ping(c2); err == nil {
		t.Error("a server with another SPIFFE ID was accepted")
	}
	if seen.Load() != 0 {
		t.Error("a request reached a server with another SPIFFE ID")
	}

	// a certificate outside the roots
	plain, _ := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen.Add(1) }))
	c3, err := New(Config{ServerURL: plain, RootCAs: x509.NewCertPool(), Basic: &BasicAuth{Username: "ada", Password: "s3cret"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c3.Close() })
	if err := ping(c3); err == nil {
		t.Error("a certificate outside the roots was accepted")
	}
	if seen.Load() != 0 {
		t.Error("a request reached a server outside the roots")
	}

	// a redirect is an error, and the Authorization header is not sent to its target
	var leaked atomic.Int32
	target, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	redirecting, _ := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+"/v1/admin/maintenance", http.StatusTemporaryRedirect)
	}))
	c4, err := New(Config{ServerURL: redirecting, RootCAs: pool, Basic: &BasicAuth{Username: "ada", Password: "s3cret"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c4.Close() })
	err = ping(c4)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("a redirect: %v", err)
	}
	if leaked.Load() != 0 {
		t.Error("the Authorization header followed a redirect")
	}
}

// TestBasicAuth: the credentials go in the Authorization header, the user
// agent identifies the client.
func TestBasicAuth(t *testing.T) {
	var user, pass, agent string
	url, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
		agent = r.UserAgent()
		_, _ = w.Write([]byte(`{}`))
	}))
	c, err := New(Config{ServerURL: url, RootCAs: pool, Basic: &BasicAuth{Username: "ada", Password: "s3cret"}, UserAgent: "tf/1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := ping(c); err != nil {
		t.Fatal(err)
	}
	if user != "ada" || pass != "s3cret" || agent != "tf/1" {
		t.Errorf("the server saw %q, %q, %q", user, pass, agent)
	}
}

// TestProblems is AC-5: every slug with a sentinel maps to it, an unknown
// slug is a *Problem, and a body that is not a problem is reported by its
// status only.
func TestProblems(t *testing.T) {
	for slug, want := range sentinels {
		url, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { problem(w, 409, slug, "the detail") }))
		c, _ := New(Config{ServerURL: url, RootCAs: pool, Basic: &BasicAuth{Username: "ada", Password: "x"}})
		err := ping(c)
		_ = c.Close()
		var p *Problem
		if !errors.As(err, &p) || p.Status != 409 || p.Slug() != slug || p.Detail != "the detail" {
			t.Errorf("%s: %#v", slug, err)
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v is not %v", slug, err, want)
		}
	}

	url, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { problem(w, 418, "a-new-slug", "teapot") }))
	c, _ := New(Config{ServerURL: url, RootCAs: pool, Basic: &BasicAuth{Username: "ada", Password: "x"}})
	t.Cleanup(func() { _ = c.Close() })
	err := ping(c)
	var p *Problem
	if !errors.As(err, &p) || p.Slug() != "a-new-slug" {
		t.Fatalf("an unknown slug: %#v", err)
	}
	for _, s := range sentinels {
		if errors.Is(err, s) {
			t.Errorf("an unknown slug is %v", s)
		}
	}

	// not a problem: the status, and none of the body
	html, pool2 := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>upstream secret-banner</html>"))
	}))
	c2, _ := New(Config{ServerURL: html, RootCAs: pool2, Basic: &BasicAuth{Username: "ada", Password: "x"}})
	t.Cleanup(func() { _ = c2.Close() })
	err = ping(c2)
	if !errors.As(err, &p) || p.Status != 502 || strings.Contains(err.Error(), "secret-banner") || p.Detail != "" {
		t.Errorf("a body that is not a problem: %#v", err)
	}
	// a JSON body that is not a problem either
	js, pool3 := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"password":"hunter2"}`))
	}))
	c3, _ := New(Config{ServerURL: js, RootCAs: pool3, Basic: &BasicAuth{Username: "ada", Password: "x"}})
	t.Cleanup(func() { _ = c3.Close() })
	if err = ping(c3); !errors.As(err, &p) || p.Status != 500 || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("a JSON body that is not a problem: %#v", err)
	}
}

// TestRetryAfter: a 503 or 429 carries the server's Retry-After.
func TestRetryAfter(t *testing.T) {
	for header, want := range map[string]time.Duration{"60": time.Minute, "": 0, "soon": 0, "99999": time.Hour, "-3": 0} {
		url, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if header != "" {
				w.Header().Set("Retry-After", header)
			}
			problem(w, 503, "maintenance", "later")
		}))
		c, _ := New(Config{ServerURL: url, RootCAs: pool, Basic: &BasicAuth{Username: "ada", Password: "x"}})
		err := ping(c)
		_ = c.Close()
		var p *Problem
		if !errors.As(err, &p) || p.RetryAfter != want {
			t.Errorf("Retry-After %q: %#v, want %s", header, err, want)
		}
	}
}

// TestBodyLimit is AC-9: a body over the limit is cut and reported.
func TestBodyLimit(t *testing.T) {
	url, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"a":"`))
		chunk := []byte(strings.Repeat("x", 1<<20))
		for range 9 {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	c, _ := New(Config{ServerURL: url, RootCAs: pool, Basic: &BasicAuth{Username: "ada", Password: "x"}})
	t.Cleanup(func() { _ = c.Close() })
	if err := ping(c); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a body of 9 MiB: %v", err)
	}
}

// TestPasswordIsRedacted is AC-8: the password is in no output, with any verb.
func TestPasswordIsRedacted(t *testing.T) {
	const pw = "hunter2-very-secret"
	basic := &BasicAuth{Username: "ada", Password: pw}
	cfg := Config{ServerURL: "https://ligo.lab:9443", RootCAs: x509.NewCertPool(), Basic: basic}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	var logged strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("config", "basic", basic, "password", basic.Password, "config", cfg)
	for name, v := range map[string]any{"basic": basic, "*basic": *basic, "password": basic.Password, "config": cfg, "*config": &cfg, "client": c, "*client": *c} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, pw) {
				t.Errorf("%s with %s prints the password: %s", name, verb, out)
			}
		}
	}
	if strings.Contains(logged.String(), pw) {
		t.Errorf("slog prints the password: %s", logged.String())
	}

	// a failing call: the error and the client's own log hold no password
	var log strings.Builder
	url, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { problem(w, 401, "unauthenticated", "no") }))
	c2, _ := New(Config{ServerURL: url, RootCAs: pool, Basic: basic, Logger: slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	t.Cleanup(func() { _ = c2.Close() })
	err = ping(c2)
	if err == nil || strings.Contains(err.Error(), pw) || strings.Contains(log.String(), pw) || strings.Contains(log.String(), "Basic ") {
		t.Errorf("error %v, log %s", err, log.String())
	}
	if !strings.Contains(log.String(), "/v1/admin/maintenance") {
		t.Errorf("the log has no path: %s", log.String())
	}
}

// TestSlugsAreMapped is the second half of AC-5: every problem slug the
// server sends is either mapped to a sentinel or listed as having none, so
// that a new server slug is a decision, not a surprise.
func TestSlugsAreMapped(t *testing.T) {
	const noSentinel = "internal"
	pattern := regexp.MustCompile(`(?:problem\(w, [^,]+, |Slug: *|refuse\(\d+, )"([a-z][a-z-]+)"`)
	found := map[string]bool{}
	err := filepath.WalkDir("../../internal", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, err := os.ReadFile(path)
		for _, m := range pattern.FindAllStringSubmatch(string(data), -1) {
			found[m[1]] = true
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) < 30 {
		t.Fatalf("found only %d slugs: the pattern no longer matches the server", len(found))
	}
	for slug := range found {
		if _, ok := sentinels[slug]; !ok && slug != noSentinel {
			t.Errorf("the server sends %q, which the client maps to no sentinel: add it to sentinels in errors.go", slug)
		}
	}
	for slug := range sentinels {
		if !found[slug] {
			t.Errorf("the client maps %q, which the server no longer sends", slug)
		}
	}
	if !slices.Contains(slices.Collect(func(yield func(string) bool) {
		for s := range found {
			if !yield(s) {
				return
			}
		}
	}), noSentinel) {
		t.Errorf("%q is no longer sent", noSentinel)
	}
}

// TestProxy: the calls go through a proxy by CONNECT, and the server is
// still verified end to end. net/http reads HTTPS_PROXY once per process, so
// the test sets the proxy on the HTTPClient's transport, which New clones;
// by default the transport takes the proxy of the environment.
func TestProxy(t *testing.T) {
	url, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	backend := strings.TrimPrefix(url, "https://")
	var connects atomic.Int32
	var wanted atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		connects.Add(1)
		wanted.Store(r.Host)
		upstream, err := net.Dial("tcp", backend) // whatever host was asked for, the test's server answers
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close() }()
		go func() { _, _ = io.Copy(conn, upstream); _ = conn.Close() }()
	}))
	t.Cleanup(proxy.Close)
	proxyURL, _ := neturl.Parse(proxy.URL)
	viaProxy := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}

	// example.com is in httptest's certificate; the proxy sends it to the test server
	c, err := New(Config{ServerURL: "https://example.com:9443", RootCAs: pool, Basic: &BasicAuth{Username: "ada", Password: "x"}, HTTPClient: viaProxy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := ping(c); err != nil {
		t.Fatal(err)
	}
	if connects.Load() != 1 || wanted.Load() != "example.com:9443" {
		t.Errorf("the proxy saw %d CONNECTs for %v", connects.Load(), wanted.Load())
	}

	// a server outside the roots fails the verification through the proxy too
	c2, err := New(Config{ServerURL: "https://example.com:9443", RootCAs: x509.NewCertPool(), Basic: &BasicAuth{Username: "ada", Password: "x"}, HTTPClient: viaProxy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	if ping(c2) == nil {
		t.Error("a server outside the roots was accepted through a proxy")
	}

	// without an HTTPClient the transport takes the proxy of the environment
	cfg := Config{RootCAs: pool}
	h, err := cfg.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	if h.Transport.(*http.Transport).Proxy == nil {
		t.Error("the default transport has no proxy function")
	}
}
