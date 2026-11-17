// Package client is the CLI's side of the admin API (§8.4): its options, the
// password prompt and the printing of results as table, JSON or YAML. The
// connection, the verification of the server, the credentials and the mapping
// of problems are pkg/adminclient's (.specs/ligo-adminclient.md §3.7).
package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"charm.land/huh/v2"
	"github.com/dihedron/ligo/internal/adminraw"
	"github.com/dihedron/ligo/pkg/adminclient"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Options is §8.4 ClientOptions.
type Options struct {
	ServerURL    string `short:"s" long:"server" env:"LIGO_SERVER_URL" default:"https://localhost:9443" description:"Admin server base URL."`
	CACert       string `long:"ca-cert" env:"LIGO_CA_CERT" description:"Path to CA certificate bundle for verifying the Admin server."`
	SpiffeSocket string `long:"spiffe-socket" env:"LIGO_SPIFFE_SOCKET" description:"SPIRE Workload API socket path for mTLS X.509-SVID authentication."`
	ServerID     string `long:"server-id" env:"LIGO_SERVER_ID" description:"SPIFFE ID the Admin server's SVID must have when it is verified with the socket's bundle (no --ca-cert); default spiffe://<the client SVID's trust domain>/ns/sys/sa/ligo."`
	Username     string `short:"u" long:"username" env:"LIGO_USERNAME" description:"LDAP username (only when server allow_basic_auth is enabled)."`
	PasswordFile string `long:"password-file" env:"LIGO_PASSWORD_FILE" description:"File containing the LDAP password (only when server allow_basic_auth is enabled). If omitted and no SPIFFE socket is set, the password is prompted for without echo."`
}

// Client calls the admin API through pkg/adminclient.
type Client struct {
	*adminclient.Client
	source *workloadapi.X509Source
}

// Do makes a call the typed methods of pkg/adminclient do not model, with the
// package's verification, credentials, limits and mapping of problems; see
// internal/adminraw.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	return adminraw.Do(ctx, c.Client, method, path, query, body, out)
}

// Problem is an RFC 9457 problem from the server (§7.2.3).
type Problem = adminclient.Problem

// prompt reads the password on a terminal without echo; tests replace it.
var prompt = func(user string) (string, error) {
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("client: no terminal to prompt for the password: use --password-file or --spiffe-socket")
	}
	var password string
	err := huh.NewInput().Title("LDAP password for " + user).EchoMode(huh.EchoModePassword).Value(&password).Run()
	return password, err
}

// socketTimeout bounds the wait for the Workload API's first SVID.
var socketTimeout = 20 * time.Second

// Connect prepares a client: with --spiffe-socket it presents the SVID of
// the Workload API, otherwise LDAP Basic credentials (§8.4).
func (o *Options) Connect(ctx context.Context) (*Client, error) {
	u, err := url.Parse(o.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("client: --server %q: an https:// URL is required", o.ServerURL)
	}
	cfg := adminclient.Config{ServerURL: strings.TrimSuffix(o.ServerURL, "/"), UserAgent: "ligo",
		HTTPClient: &http.Client{Timeout: 90 * time.Second}}
	if o.CACert != "" {
		pem, err := os.ReadFile(o.CACert)
		if err != nil {
			return nil, fmt.Errorf("client: --ca-cert: %w", err)
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client: --ca-cert %s: no certificate", o.CACert)
		}
	}
	c := &Client{}
	if o.SpiffeSocket != "" {
		sctx, cancel := context.WithTimeout(ctx, socketTimeout)
		c.source, err = workloadapi.NewX509Source(sctx, workloadapi.WithClientOptions(workloadapi.WithAddr(o.SpiffeSocket)))
		cancel() // the context only bounds the wait for the first SVID
		if err != nil {
			return nil, fmt.Errorf("client: --spiffe-socket %s: no answer from the Workload API (is the SPIRE agent running?): %w", o.SpiffeSocket, err)
		}
	}
	if o.Username != "" || o.SpiffeSocket == "" {
		user, password, err := o.credentials()
		if err != nil {
			c.Close()
			return nil, err
		}
		cfg.Basic = &adminclient.BasicAuth{Username: user, Password: adminclient.Secret(password)}
	}
	if err := o.verification(&cfg, c.source); err != nil {
		c.Close()
		return nil, err
	}
	if cfg.Basic == nil {
		cfg.X509Source = c.source // the client SVID, over mTLS
	}
	if c.Client, err = adminclient.New(cfg); err != nil {
		c.Close()
		return nil, fmt.Errorf("client: %w", err)
	}
	return c, nil
}

// verification says how the server is verified: with --ca-cert; else, with a
// socket, by the SPIFFE ID --server-id (by default ligo's, in the trust
// domain of the SVID) against the source's bundle; else with the system's
// roots.
func (o *Options) verification(cfg *adminclient.Config, source *workloadapi.X509Source) error {
	switch {
	case cfg.RootCAs != nil:
		return nil
	case source == nil:
		pool, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("client: the system's certificates: %w", err)
		}
		cfg.RootCAs = pool
		return nil
	}
	id := o.ServerID
	if id == "" {
		svid, err := source.GetX509SVID()
		if err != nil {
			return fmt.Errorf("client: --spiffe-socket: %w", err)
		}
		id = "spiffe://" + svid.ID.TrustDomain().Name() + "/ns/sys/sa/ligo"
	}
	if _, err := spiffeid.FromString(id); err != nil {
		return fmt.Errorf("client: --server-id %q: %w", id, err)
	}
	cfg.ServerID, cfg.Bundles = id, source
	return nil
}

// credentials are the LDAP username and the password from --password-file,
// which nobody but its owner may read, or from the prompt.
func (o *Options) credentials() (string, string, error) {
	if o.Username == "" {
		return "", "", errors.New("client: --spiffe-socket, or --username with --password-file or a terminal, is required")
	}
	if o.PasswordFile == "" {
		password, err := prompt(o.Username)
		return o.Username, password, err
	}
	info, err := os.Stat(o.PasswordFile)
	if err != nil {
		return "", "", fmt.Errorf("client: --password-file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("client: --password-file %s must not be accessible by group or others (mode %v)", o.PasswordFile, info.Mode().Perm())
	}
	data, err := os.ReadFile(o.PasswordFile)
	if err != nil {
		return "", "", fmt.Errorf("client: --password-file: %w", err)
	}
	return o.Username, strings.TrimRight(string(data), "\r\n"), nil
}

// Close releases the connections and the Workload API source.
func (c *Client) Close() {
	if c.Client != nil {
		_ = c.Client.Close()
	}
	if c.source != nil {
		_ = c.source.Close()
	}
}
