package workloadhttp

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	workloadv1alpha1 "github.com/dihedron/ligo/api/gen/workload/v1alpha1"
	"github.com/dihedron/ligo/internal/resolution"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// grpcClient dials the test server over TLS, presenting cert if given.
func (v *env) grpcClient(t *testing.T, cert ...tls.Certificate) workloadv1alpha1.WorkloadBindingServiceClient {
	t.Helper()
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: cert} //nolint:gosec // the server's SPIFFE ID is not under test
	conn, err := grpc.NewClient("passthrough:///"+strings.TrimPrefix(v.srv.URL, "https://"), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return workloadv1alpha1.NewWorkloadBindingServiceClient(conn)
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// TestGRPCBindings: GetBindings on the REST port answers what REST does,
// with the same ETag, and not_modified for a known one (§7.1).
func TestGRPCBindings(t *testing.T) {
	v, f, c := apiSetup(t)
	rest, _ := v.fetch(t, c, "/v1/bindings?target=ledger-schema", "")
	g := v.grpcClient(t, certificate(t, v.ca, worker))
	resp, err := g.GetBindings(ctx(t), &workloadv1alpha1.GetBindingsRequest{TargetFilter: "ledger-schema", PlatformTypeFilter: "oracle.v1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetEtag() != rest.Header.Get("ETag") || resp.GetCallerSpiffeId() != worker || resp.GetNotModified() || len(resp.GetItems()) != 1 {
		t.Fatalf("GetBindings: %v (REST ETag %s)", resp, rest.Header.Get("ETag"))
	}
	it := resp.GetItems()[0]
	if it.GetName() != "workers-ledger" || it.GetRevision() != 4 || it.GetSpec().GetFields()["host"].GetStringValue() != "ledger-db" ||
		it.GetAuth().GetFields()["secretStoreInstance"].GetStringValue() != "vault-prod" || !it.GetUpdatedAt().AsTime().Equal(f.list[0].UpdatedAt) {
		t.Errorf("item: %v", it)
	}
	if f.target != "ledger-schema" || f.ptype != "oracle.v1" {
		t.Errorf("filters: %q %q", f.target, f.ptype)
	}
	again, err := g.GetBindings(ctx(t), &workloadv1alpha1.GetBindingsRequest{TargetFilter: "ledger-schema", KnownEtag: resp.GetEtag()})
	if err != nil || !again.GetNotModified() || len(again.GetItems()) != 0 || again.GetEtag() != resp.GetEtag() {
		t.Errorf("known ETag: %v %v", again, err)
	}
	f.err = resolution.ErrStale
	if _, err := g.GetBindings(ctx(t), &workloadv1alpha1.GetBindingsRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("stale: %v", err)
	}
}

// TestGRPCFlows: GetFlows answers the effective flows with their port
// ranges and the REST ETag.
func TestGRPCFlows(t *testing.T) {
	v, _, c := apiSetup(t)
	rest, _ := v.fetch(t, c, "/v1/flows", "")
	resp, err := v.grpcClient(t, certificate(t, v.ca, worker)).GetFlows(ctx(t), &workloadv1alpha1.GetFlowsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetEtag() != rest.Header.Get("ETag") || len(resp.GetItems()) != 1 || len(resp.GetItems()[0].GetFlows()) != 4 {
		t.Fatalf("GetFlows: %v", resp)
	}
	first := resp.GetItems()[0].GetFlows()[0]
	if first.GetDeclaredBy() != "target:ledger-schema" || len(first.GetPorts()) != 1 || first.GetPorts()[0].GetLow() != 1522 || first.GetPorts()[0].GetHigh() != 1522 {
		t.Errorf("target flow: %v", first)
	}
}

// TestGRPCErrors: authentication and rate limiting answer gRPC codes, not
// HTTP statuses; a JWT-SVID travels as authorization metadata.
func TestGRPCErrors(t *testing.T) {
	v, _, _ := apiSetup(t)
	if _, err := v.grpcClient(t).GetBindings(ctx(t), &workloadv1alpha1.GetBindingsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no credentials: %v", err)
	}
	v.s.Listener.AuthModes = append(v.s.Listener.AuthModes, "jwt_svid")
	now := time.Now()
	md := metadata.AppendToOutgoingContext(ctx(t), "authorization", "Bearer "+v.token(t, claims(worker, audience, now, now.Add(time.Minute))))
	if resp, err := v.grpcClient(t).GetBindings(md, &workloadv1alpha1.GetBindingsRequest{}); err != nil || resp.GetCallerSpiffeId() != worker {
		t.Errorf("JWT-SVID: %v %v", resp, err)
	}
	v.s.Listener.RateLimit.Burst = 1
	g := v.grpcClient(t, certificate(t, v.ca, "spiffe://prod.lab/ns/app/sa/busy"))
	_, _ = g.GetBindings(ctx(t), &workloadv1alpha1.GetBindingsRequest{})
	if _, err := g.GetBindings(ctx(t), &workloadv1alpha1.GetBindingsRequest{}); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("rate limited: %v", err)
	}
}
