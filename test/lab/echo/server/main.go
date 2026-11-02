package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "echo-server:", err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", ModeSVID, "svid (SPIFFE IDs on the access list) or password (users)")
	data := flag.String("data", ":7101", "the data address")
	control := flag.String("control", ":7102", "the control API's address")
	statePath := flag.String("state", "/var/lib/echo-svid/state.json", "the state file")
	socket := flag.String("socket", "unix:///run/spire/prod/agent.sock", "the SPIRE agent's Workload API")
	td := flag.String("trust-domain", "prod.lab", "the clients' trust domain")
	controlID := flag.String("control-id", "spiffe://prod.lab/ligo/plugin/target-echo", "the only SPIFFE ID the control API admits")
	flag.Parse()
	if *mode != ModeSVID && *mode != ModePassword {
		return fmt.Errorf("--mode %q: svid or password", *mode)
	}
	trustDomain, err := spiffeid.TrustDomainFromString(*td)
	if err != nil {
		return err
	}
	cid, err := spiffeid.FromString(*controlID)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(*socket)))
	if err != nil {
		return fmt.Errorf("the SPIRE agent: %w", err)
	}
	defer func() { _ = source.Close() }()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("mode", *mode)
	s := &Server{Mode: *mode, TrustDomain: trustDomain, ControlID: cid, StatePath: *statePath, SVIDs: source, Bundles: source, Log: log}
	if err := s.load(); err != nil {
		return err
	}
	dl, err := net.Listen("tcp", *data)
	if err != nil {
		return err
	}
	cs := s.Control()
	cs.Addr = *control
	go func() {
		if err := cs.ListenAndServeTLS("", ""); err != nil {
			log.Error("control API", "error", err)
			stop()
		}
	}()
	go func() { <-ctx.Done(); _ = cs.Close() }()
	log.Info("serving", "data", *data, "control", *control)
	return s.Serve(ctx, dl)
}
