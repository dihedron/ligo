// Package client is the CLI's side of the admin API (§8.4): it connects
// with an X.509-SVID or LDAP Basic credentials, verifies the server, turns
// problems into errors and prints results as table, JSON or YAML.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"charm.land/huh/v2"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
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

// Client calls the admin API.
type Client struct {
	base       string
	http       *http.Client
	user, pass string
	source     *workloadapi.X509Source
}

// prompt reads the password on a terminal without echo; tests replace it.
var prompt = func(user string) (string, error) {
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("client: no terminal to prompt for the password: use --password-file or --spiffe-socket")
	}
	var password string
	err := huh.NewInput().Title("LDAP password for " + user).EchoMode(huh.EchoModePassword).Value(&password).Run()
	return password, err
}

// Connect prepares a client: with --spiffe-socket it presents the SVID of
// the Workload API, otherwise LDAP Basic credentials (§8.4).
func (o *Options) Connect(ctx context.Context) (*Client, error) {
	u, err := url.Parse(o.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("client: --server %q: an https:// URL is required", o.ServerURL)
	}
	c := &Client{base: strings.TrimSuffix(o.ServerURL, "/")}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
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
	if o.SpiffeSocket != "" {
		if c.source, err = workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(o.SpiffeSocket))); err != nil {
			return nil, fmt.Errorf("client: --spiffe-socket: %w", err)
		}
		if cfg, err = o.svidConfig(cfg, c.source); err != nil {
			c.Close()
			return nil, err
		}
	}
	if o.Username != "" || o.SpiffeSocket == "" {
		if c.user, c.pass, err = o.credentials(); err != nil {
			c.Close()
			return nil, err
		}
	}
	c.http = &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	return c, nil
}

// svidConfig presents the source's SVID, unless --username asks for Basic
// credentials; without --ca-cert the server is verified with the source's
// bundle and must be exactly --server-id.
func (o *Options) svidConfig(cfg *tls.Config, source *workloadapi.X509Source) (*tls.Config, error) {
	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("client: --spiffe-socket: %w", err)
	}
	if cfg.RootCAs != nil {
		if o.Username == "" {
			cfg.GetClientCertificate = tlsconfig.GetClientCertificate(source)
		}
		return cfg, nil
	}
	id := o.ServerID
	if id == "" {
		id = "spiffe://" + svid.ID.TrustDomain().Name() + "/ns/sys/sa/ligo"
	}
	server, err := spiffeid.FromString(id)
	if err != nil {
		return nil, fmt.Errorf("client: --server-id %q: %w", id, err)
	}
	if o.Username != "" {
		return tlsconfig.TLSClientConfig(source, tlsconfig.AuthorizeID(server)), nil
	}
	return tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(server)), nil
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

// Close releases the Workload API source.
func (c *Client) Close() {
	if c.source != nil {
		_ = c.source.Close()
	}
}

// Problem is an RFC 9457 problem from the server (§7.2.3).
type Problem struct {
	Status int    `json:"status"`
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func (p *Problem) Error() string {
	return fmt.Sprintf("%d %s: %s", p.Status, strings.TrimPrefix(p.Type, "urn:ligo:problem:"), p.Detail)
}

// Do sends body as JSON to path with query and decodes the answer into out
// (any JSON, when out is *any); a problem is a *Problem error.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	target := c.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		p := &Problem{Status: resp.StatusCode}
		if json.Unmarshal(data, p) != nil || p.Type == "" {
			p.Type, p.Detail = "http", strings.TrimSpace(string(data))
		}
		return p
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}
