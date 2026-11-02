package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() { os.Exit(realMain()) }

// realMain wires the client to the SPIRE agent and the lab CA.
func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socket == "" {
		socket = "unix:///run/spire/prod/agent.sock"
	}
	caFile := os.Getenv("ECHO_CA_FILE")
	if caFile == "" {
		caFile = "/etc/ligo-lab/ca.crt"
	}
	opts := workloadapi.WithClientOptions(workloadapi.WithAddr(socket))
	source, err := workloadapi.NewX509Source(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: the SPIRE agent:", err)
		return exitError
	}
	defer func() { _ = source.Close() }()
	roots := x509.NewCertPool()
	if pem, err := os.ReadFile(caFile); err == nil { //nolint:gosec // a lab path from the environment
		roots.AppendCertsFromPEM(pem)
	}
	jwt := func(ctx context.Context, audience string) (string, error) {
		client, err := workloadapi.New(ctx, workloadapi.WithAddr(socket))
		if err != nil {
			return "", err
		}
		defer func() { _ = client.Close() }()
		svid, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
		if err != nil {
			return "", err
		}
		return svid.Marshal(), nil
	}
	return run(ctx, os.Args[1:], os.Stdout, deps{SVIDs: source, Bundles: source, JWT: jwt, Roots: roots})
}
