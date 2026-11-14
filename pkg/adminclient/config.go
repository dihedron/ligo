package adminclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// X509Source gives the caller's SVID and the bundles to verify the server
// with; a *workloadapi.X509Source is one.
type X509Source interface {
	x509svid.Source
	x509bundle.Source
}

// Config configures a Client. It has no flag and no environment variable:
// those belong to the programs that use the package.
type Config struct {
	// ServerURL is the admin API, an https URL such as https://ligo.example:9443;
	// a path is kept as a prefix.
	ServerURL string

	// The server is verified by RootCAs, or by ServerID (its SPIFFE ID)
	// against Bundles, which is X509Source when that is set and Bundles is
	// not. One of the two is required; there is no way to skip it.
	RootCAs  *x509.CertPool
	ServerID string
	Bundles  x509bundle.Source

	// The caller authenticates with X509Source (its SVID, over mTLS) or with
	// Basic (LDAP credentials, if the server allows them); exactly one.
	X509Source X509Source
	Basic      *BasicAuth

	Logger    *slog.Logger // default slog.Default(); it gets method, path and status of each call, never a body or a header
	UserAgent string       // default "ligo-adminclient"

	// HTTPClient sets the timeout and, when its Transport is an *http.Transport,
	// its proxy and connection limits. Without one, the calls use the proxy
	// of the standard HTTPS_PROXY, HTTP_PROXY and NO_PROXY variables, as
	// net/http does. A proxy only tunnels (CONNECT): the TLS session, the
	// server's verification and the client's SVID are end to end, so a proxy
	// that intercepts TLS fails the verification unless its CA is in RootCAs.
	// The TLS configuration and the redirect policy are replaced, never merged.
	HTTPClient *http.Client

	// MaxRetries is how often a GET is repeated after a broken connection or a
	// 429, 502, 503 or 504 (0: twice; -1: never), with a backoff from 200 ms to
	// 5 s and the server's Retry-After when it is at most 30 s. A mutation is
	// never repeated.
	MaxRetries int
}

// String hides what could identify the caller; %v of a Config is safe to log.
func (c Config) String() string {
	return fmt.Sprintf("adminclient.Config{ServerURL: %s}", c.ServerURL)
}

// GoString is String.
func (c Config) GoString() string { return c.String() }

const (
	defaultMaxRetries = 2
	defaultTimeout    = 60 * time.Second
)

// validate checks the configuration and returns the base URL.
func (c *Config) validate() (*url.URL, error) {
	u, err := url.Parse(c.ServerURL)
	switch {
	case c.ServerURL == "":
		return nil, errors.New("adminclient: ServerURL is required")
	case err != nil || u.Host == "":
		return nil, fmt.Errorf("adminclient: ServerURL %q: an https URL is required", c.ServerURL)
	case u.Scheme != "https":
		return nil, fmt.Errorf("adminclient: ServerURL %q: only https is accepted", c.ServerURL)
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("adminclient: ServerURL has credentials, a query or a fragment: none is accepted")
	}
	if c.MaxRetries < -1 {
		return nil, fmt.Errorf("adminclient: MaxRetries %d: -1 (never), 0 (the default) or more", c.MaxRetries)
	}
	if (c.X509Source == nil) == (c.Basic == nil) {
		return nil, errors.New("adminclient: exactly one authentication is required: X509Source or Basic")
	}
	if b := c.Basic; b != nil {
		if b.Username == "" {
			return nil, errors.New("adminclient: Basic.Username is required")
		}
		if b.Password == "" {
			return nil, errors.New("adminclient: Basic.Password is required")
		}
	}
	switch {
	case c.RootCAs == nil && c.ServerID == "":
		return nil, errors.New("adminclient: the server must be verified: RootCAs, or ServerID with Bundles")
	case c.ServerID != "":
		if _, err := spiffeid.FromString(c.ServerID); err != nil {
			return nil, fmt.Errorf("adminclient: ServerID: %w", err)
		}
		if c.RootCAs == nil && c.Bundles == nil && c.X509Source == nil {
			return nil, errors.New("adminclient: ServerID needs Bundles (or an X509Source) to verify the server against")
		}
	case c.Bundles != nil && c.RootCAs == nil:
		return nil, errors.New("adminclient: Bundles needs the ServerID to verify")
	}
	if c.HTTPClient != nil && c.HTTPClient.Transport != nil {
		if _, ok := c.HTTPClient.Transport.(*http.Transport); !ok {
			return nil, errors.New("adminclient: HTTPClient.Transport must be an *http.Transport: its TLS configuration is replaced")
		}
	}
	return u, nil
}

// tlsConfig is the TLS configuration of the calls: the server is verified by
// the roots or by its SPIFFE ID, and the client presents its SVID if it has
// one.
func (c *Config) tlsConfig() (*tls.Config, error) {
	var id spiffeid.ID
	if c.ServerID != "" {
		var err error
		if id, err = spiffeid.FromString(c.ServerID); err != nil {
			return nil, err
		}
	}
	bundles := c.Bundles
	if bundles == nil && c.X509Source != nil {
		bundles = c.X509Source
	}
	var tc *tls.Config
	switch {
	case c.RootCAs != nil && c.X509Source != nil:
		tc = &tls.Config{RootCAs: c.RootCAs, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return tlsconfig.GetCertificate(c.X509Source)(nil)
		}}
	case c.RootCAs != nil:
		tc = &tls.Config{RootCAs: c.RootCAs}
	case c.X509Source != nil:
		tc = tlsconfig.MTLSClientConfig(c.X509Source, bundles, tlsconfig.AuthorizeID(id))
	default:
		tc = tlsconfig.TLSClientConfig(bundles, tlsconfig.AuthorizeID(id))
	}
	tc.MinVersion = tls.VersionTLS13 // the admin API is ligo's own: nothing older is needed
	return tc, nil
}

// httpClient builds the client of the calls, with this package's TLS
// configuration and without redirects (T-A1).
func (c *Config) httpClient() (*http.Client, error) {
	tc, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	var tr *http.Transport
	timeout := defaultTimeout
	if h := c.HTTPClient; h != nil {
		if t, ok := h.Transport.(*http.Transport); ok {
			tr = t.Clone()
		}
		if h.Timeout != 0 {
			timeout = h.Timeout
		}
	}
	if tr == nil {
		tr = &http.Transport{
			Proxy: http.ProxyFromEnvironment, MaxIdleConns: 10, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ForceAttemptHTTP2: true,
		}
	}
	tr.TLSClientConfig = tc
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (c *Config) userAgent() string {
	if c.UserAgent != "" {
		return strings.TrimSpace(c.UserAgent)
	}
	return "ligo-adminclient"
}
