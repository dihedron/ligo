// Command echo-client is the lab's echo client (lab only, not hardened;
// .specs/ligo-echo-target.md): it finds its binding to an echo target with
// ligo's Go client SDK (pkg/client), authenticates as the binding says (its
// SVID, or the password OpenBao keeps for it) and prints what the server
// echoes.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dihedron/ligo/pkg/client"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
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
	X509  client.X509Source
	JWT   jwtsvid.Source
	Roots *x509.CertPool // the lab CA, of OpenBao's certificate
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
	ligo := fs.String("ligo", "ligo1.ligo.lab:8443", "ligo's workload API, host:port")
	ligoID := fs.String("ligo-id", "spiffe://prod.lab/ns/sys/sa/ligo", "ligo's SPIFFE ID")
	transport := fs.String("transport", "rest", "how to call ligo: rest or grpc")
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
	sdk, err := client.New(ctx, client.Config{Address: *ligo, ServerID: *ligoID, Transport: client.Transport(*transport),
		X509Source: d.X509, JWTSource: d.JWT, StoreRoots: d.Roots})
	if err != nil {
		return fail("%v", err)
	}
	defer func() { _ = sdk.Close() }()
	c := connection{endpoint: *direct, serverID: *serverID, mode: *mode, user: *user, password: *password}
	if *direct == "" {
		if *target == "" {
			return fail("--target or --direct is required")
		}
		bindings, err := sdk.Bindings(ctx, client.Filter{Target: *target})
		if err != nil {
			return fail("ligo's workload API: %v", err)
		}
		if len(bindings) == 0 {
			_, _ = fmt.Fprintln(out, "no binding")
			return exitNoBinding
		}
		b := bindings[0]
		c = connection{endpoint: b.Endpoint()}
		c.serverID, _ = b.Spec["serverId"].(string)
		c.mode, _ = b.Spec["mode"].(string)
		cred, err := sdk.Credential(ctx, b)
		switch {
		case err == nil:
			c.user, c.password = cred.Username, cred.Password
		case !errors.Is(err, client.ErrNoCredential) || c.mode == "password":
			return fail("the binding's password: %v", err)
		}
		_, _ = fmt.Fprintf(out, "binding %s: %s mode, %s\n", b.Name, c.mode, c.endpoint)
	}
	answer, err := echo(ctx, sdk, c, *message)
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

// echo connects to the server, verifying its SPIFFE ID, presents the
// client's SVID, authenticates in the password mode, sends the message and
// returns the answer.
func echo(ctx context.Context, sdk *client.Client, c connection, message string) (string, error) {
	id, err := spiffeid.FromString(c.serverID)
	if err != nil {
		return "", fmt.Errorf("the server's SPIFFE ID: %w", err)
	}
	if c.mode != "svid" && c.mode != "password" {
		return "", fmt.Errorf("mode %q: svid or password", c.mode)
	}
	dialer := &tls.Dialer{Config: sdk.TLSConfig(id)}
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
