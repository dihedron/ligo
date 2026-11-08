// Command echo-client is the lab's echo client (lab only, not hardened;
// .specs/ligo-echo-target.md): it finds its binding to an echo target
// through ligo's workload API, authenticates as the binding says (its SVID,
// or the password OpenBao keeps for it) and prints what the server echoes.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Exit codes (.specs/ligo-echo-target.md).
const (
	exitEchoed    = 0
	exitError     = 1
	exitNoBinding = 2
	exitDenied    = 3
)

// deps are what the client takes from its environment.
type deps struct {
	SVIDs   x509svid.Source
	Bundles x509bundle.Source
	JWT     func(ctx context.Context, audience string) (string, error) // a JWT-SVID for audience
	Roots   *x509.CertPool                                             // the lab CA, of OpenBao's certificate
}

// binding is an item of GET /v1/bindings (§3.6) as an echo target fills it.
type binding struct {
	Name string `json:"name"`
	Spec struct {
		Endpoint string `json:"endpoint"`
		ServerID string `json:"serverId"`
		Mode     string `json:"mode"`
		User     string `json:"user"`
	} `json:"spec"`
	Auth struct {
		SecretStorageStrategy string `json:"secretStorageStrategy"`
		Config                struct {
			Address    string `json:"address"`
			SecretPath string `json:"secretPath"`
			AuthMount  string `json:"authMount"`
			Role       string `json:"role"`
		} `json:"config"`
	} `json:"auth"`
}

// connection is how to reach and authenticate to the echo server.
type connection struct {
	endpoint, serverID, mode, user, password string
}

func run(ctx context.Context, args []string, out io.Writer, d deps) int {
	fs := flag.NewFlagSet("echo-client", flag.ContinueOnError)
	fs.SetOutput(out)
	target := fs.String("target", "", "the echo target to find a binding to")
	message := fs.String("message", "hello", "the text to send")
	ligo := fs.String("ligo", "https://ligo1.ligo.lab:8443", "ligo's workload API")
	ligoID := fs.String("ligo-id", "spiffe://prod.lab/ns/sys/sa/ligo", "ligo's SPIFFE ID")
	audience := fs.String("audience", "https://bao-prod.ligo.lab", "the audience of the JWT-SVID for OpenBao")
	direct := fs.String("direct", "", "host:port: connect without asking ligo")
	mode := fs.String("mode", "svid", "with --direct: svid or password")
	user := fs.String("user", "", "with --direct --mode password")
	password := fs.String("password", "", "with --direct --mode password")
	serverID := fs.String("server-id", "spiffe://prod.lab/ns/lab/sa/echo-server", "with --direct: the server's SPIFFE ID")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(out, "error: "+format+"\n", a...)
		return exitError
	}
	if strings.ContainsAny(*message, "\n\t") {
		return fail("--message: one line without tabs")
	}
	c := connection{endpoint: *direct, serverID: *serverID, mode: *mode, user: *user, password: *password}
	if *direct == "" {
		if *target == "" {
			return fail("--target or --direct is required")
		}
		b, found, err := lookup(ctx, d, *ligo, *ligoID, *target)
		if err != nil {
			return fail("%v", err)
		}
		if !found {
			_, _ = fmt.Fprintln(out, "no binding")
			return exitNoBinding
		}
		c = connection{endpoint: b.Spec.Endpoint, serverID: b.Spec.ServerID, mode: b.Spec.Mode}
		if b.Spec.Mode == "password" {
			if c.user, c.password, err = secret(ctx, d, b, *audience); err != nil {
				return fail("the binding's password: %v", err)
			}
		}
		_, _ = fmt.Fprintf(out, "binding %s: %s mode, %s\n", b.Name, c.mode, c.endpoint)
	}
	answer, err := echo(ctx, d, c, *message)
	if err != nil {
		return fail("%v", err)
	}
	_, _ = fmt.Fprintln(out, answer)
	switch {
	case answer == "denied":
		return exitDenied
	case strings.HasPrefix(answer, *message+"\t"):
		return exitEchoed
	}
	return fail("unexpected answer")
}

// lookup asks ligo for the caller's bindings to target, over mTLS with the
// caller's SVID, accepting only ligo's SPIFFE ID.
func lookup(ctx context.Context, d deps, base, ligoID, target string) (binding, bool, error) {
	id, err := spiffeid.FromString(ligoID)
	if err != nil {
		return binding{}, false, fmt.Errorf("--ligo-id: %w", err)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsconfig.MTLSClientConfig(d.SVIDs, d.Bundles, tlsconfig.AuthorizeID(id))}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/bindings?target="+url.QueryEscape(target), nil)
	resp, err := client.Do(req)
	if err != nil {
		return binding{}, false, fmt.Errorf("ligo's workload API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return binding{}, false, fmt.Errorf("ligo's workload API: %s", resp.Status)
	}
	var doc struct {
		Items []binding `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return binding{}, false, fmt.Errorf("ligo's workload API: %w", err)
	}
	if len(doc.Items) == 0 {
		return binding{}, false, nil
	}
	return doc.Items[0], true, nil
}

// secret logs in to OpenBao with a JWT-SVID through the binding's role and
// reads the binding's user and password.
func secret(ctx context.Context, d deps, b binding, audience string) (string, string, error) {
	cfg := b.Auth.Config
	if cfg.Address == "" || cfg.SecretPath == "" || cfg.AuthMount == "" || cfg.Role == "" {
		return "", "", errors.New("the binding names no OpenBao role and secret")
	}
	jwt, err := d.JWT(ctx, audience)
	if err != nil {
		return "", "", fmt.Errorf("JWT-SVID: %w", err)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: d.Roots, MinVersion: tls.VersionTLS12}}}
	call := func(method, path, token string, body, out any) error {
		var rd io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			rd = bytes.NewReader(data)
		}
		req, _ := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(cfg.Address, "/")+"/v1/"+path, rd)
		if token != "" {
			req.Header.Set("X-Vault-Token", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s %s: %s", method, path, resp.Status)
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}
	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := call(http.MethodPost, "auth/"+cfg.AuthMount+"/login", "", map[string]string{"role": cfg.Role, "jwt": jwt}, &login); err != nil {
		return "", "", fmt.Errorf("OpenBao login: %w", err)
	}
	var kv struct {
		Data struct {
			Data struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := call(http.MethodGet, cfg.SecretPath, login.Auth.ClientToken, nil, &kv); err != nil {
		return "", "", fmt.Errorf("OpenBao secret: %w", err)
	}
	return kv.Data.Data.Username, kv.Data.Data.Password, nil
}

// echo connects to the server, verifying its SPIFFE ID, presents the
// client's SVID, authenticates in the password mode, sends the message and
// returns the answer.
func echo(ctx context.Context, d deps, c connection, message string) (string, error) {
	id, err := spiffeid.FromString(c.serverID)
	if err != nil {
		return "", fmt.Errorf("the server's SPIFFE ID: %w", err)
	}
	if c.mode != "svid" && c.mode != "password" {
		return "", fmt.Errorf("mode %q: svid or password", c.mode)
	}
	dialer := &tls.Dialer{Config: tlsconfig.MTLSClientConfig(d.SVIDs, d.Bundles, tlsconfig.AuthorizeID(id))}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", c.endpoint)
	if err != nil {
		return "", fmt.Errorf("the echo server: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	lines := message + "\n"
	if c.mode == "password" {
		lines = "auth " + c.user + " " + c.password + "\n" + lines
	}
	if _, err := io.WriteString(conn, lines); err != nil {
		return "", err
	}
	answer, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && answer == "" {
		return "", fmt.Errorf("the echo server: %w", err)
	}
	return strings.TrimSuffix(answer, "\n"), nil
}
