package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() { os.Exit(realMain()) }

// realMain wires the client to the lab CA; the SDK reaches the SPIRE agent
// at SPIFFE_ENDPOINT_SOCKET itself.
func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if os.Getenv("SPIFFE_ENDPOINT_SOCKET") == "" {
		if err := os.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/prod/agent.sock"); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
	}
	caFile := os.Getenv("ECHO_CA_FILE")
	if caFile == "" {
		caFile = "/etc/ligo-lab/ca.crt"
	}
	roots := x509.NewCertPool()
	if pem, err := os.ReadFile(caFile); err == nil { //nolint:gosec // a lab path from the environment
		roots.AppendCertsFromPEM(pem)
	}
	return run(ctx, os.Args[1:], os.Stdout, deps{Roots: roots})
}
