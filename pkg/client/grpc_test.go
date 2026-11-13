package client

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	workloadv1alpha1 "github.com/dihedron/ligo/api/gen/workload/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeService answers WorkloadBindingService with fixed items, or err.
type fakeService struct {
	workloadv1alpha1.UnimplementedWorkloadBindingServiceServer
	bindings []*workloadv1alpha1.WorkloadBinding
	flows    []*workloadv1alpha1.BindingFlows
	err      error
	requests []string // filters and known ETags, in order
}

func (f *fakeService) GetBindings(_ context.Context, r *workloadv1alpha1.GetBindingsRequest) (*workloadv1alpha1.GetBindingsResponse, error) {
	f.requests = append(f.requests, "bindings "+r.GetTargetFilter()+" "+r.GetPlatformTypeFilter()+" "+r.GetKnownEtag())
	if f.err != nil {
		return nil, f.err
	}
	if r.GetKnownEtag() == "e1" {
		return &workloadv1alpha1.GetBindingsResponse{NotModified: true, Etag: "e1"}, nil
	}
	return &workloadv1alpha1.GetBindingsResponse{Etag: "e1", Items: f.bindings}, nil
}

func (f *fakeService) GetFlows(_ context.Context, r *workloadv1alpha1.GetFlowsRequest) (*workloadv1alpha1.GetFlowsResponse, error) {
	f.requests = append(f.requests, "flows "+r.GetTargetFilter()+" "+r.GetKnownEtag())
	if f.err != nil {
		return nil, f.err
	}
	if r.GetKnownEtag() == "e1" {
		return &workloadv1alpha1.GetFlowsResponse{NotModified: true, Etag: "e1"}, nil
	}
	return &workloadv1alpha1.GetFlowsResponse{Etag: "e1", Items: f.flows}, nil
}

// serveGRPC starts the fake behind mTLS as id.
func (v *env) serveGRPC(t *testing.T, id string, f *fakeService) string {
	t.Helper()
	g := grpc.NewServer()
	workloadv1alpha1.RegisterWorkloadBindingServiceServer(g, f)
	return v.serve(t, id, http.HandlerFunc(g.ServeHTTP))
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestGRPC is CS-2 and CS-3 on gRPC: the same values as REST decodes, the
// filters, and the remembered list when not modified.
func TestGRPC(t *testing.T) {
	v := newEnv(t)
	f := &fakeService{
		bindings: []*workloadv1alpha1.WorkloadBinding{{Id: "0192", Name: "workers-ledger", Source: "workers", Target: "ledger", AccessLevel: "write",
			PlatformType: "postgres", Platform: "pg-prod", Revision: 4, UpdatedAt: timestamppb.New(time.Date(2026, 10, 16, 7, 2, 11, 0, time.UTC)),
			Spec: mustStruct(t, map[string]any{"endpoint": "db.lab:5432", "port": 5432}),
			Auth: mustStruct(t, map[string]any{"secretStorageStrategy": "vault-dynamic", "secretStoreType": "vault", "secretStoreInstance": "vault-prod",
				"config": map[string]any{"address": "https://vault.lab:8200", "credsPath": "database/creds/binding-0192"}})}},
		flows: []*workloadv1alpha1.BindingFlows{{Binding: "workers-ledger", Source: "workers", Target: "ledger", Flows: []*workloadv1alpha1.NetworkFlow{{
			Name: "db", Purpose: "DATA", Protocol: "TCP", Destination: "db.lab", Ports: []*workloadv1alpha1.PortRange{{Low: 5432, High: 5432}, {Low: 6000, High: 6010}},
			Tls: true, ServerName: "db.lab", Description: "d", DeclaredBy: "target:ledger"}}}},
	}
	c := v.client(t, v.serveGRPC(t, ligoID, f), GRPC)
	want := []Binding{{ID: "0192", Name: "workers-ledger", Source: "workers", Target: "ledger", AccessLevel: "write", PlatformType: "postgres",
		Platform: "pg-prod", Revision: 4, UpdatedAt: time.Date(2026, 10, 16, 7, 2, 11, 0, time.UTC),
		Spec: map[string]any{"endpoint": "db.lab:5432", "port": float64(5432)},
		Auth: Auth{Strategy: "vault-dynamic", StoreType: "vault", StoreInstance: "vault-prod",
			Config: map[string]string{"address": "https://vault.lab:8200", "credsPath": "database/creds/binding-0192"}}}}
	for range 2 {
		got, err := c.Bindings(t.Context(), Filter{Target: "ledger", PlatformType: "postgres"})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("bindings\n got %+v (%v)\nwant %+v", got, err, want)
		}
	}
	wantFlows := []BindingFlows{{Binding: "workers-ledger", Source: "workers", Target: "ledger", Flows: []Flow{{Name: "db", Purpose: "DATA", Protocol: "TCP",
		Destination: "db.lab", Ports: []PortRange{{5432, 5432}, {6000, 6010}}, TLS: true, ServerName: "db.lab", Description: "d", DeclaredBy: "target:ledger"}}}}
	for range 2 {
		got, err := c.Flows(t.Context(), Filter{Target: "ledger", PlatformType: "ignored"})
		if err != nil || !reflect.DeepEqual(got, wantFlows) {
			t.Fatalf("flows %+v (%v)", got, err)
		}
	}
	if want := []string{"bindings ledger postgres ", "bindings ledger postgres e1", "flows ledger ", "flows ledger e1"}; !reflect.DeepEqual(f.requests, want) {
		t.Errorf("requests %q", f.requests)
	}
	f.bindings, f.flows = nil, nil
	if none, err := c.Bindings(t.Context(), Filter{}); err != nil || none == nil || len(none) != 0 {
		t.Errorf("no binding: %v (%v)", none, err)
	}
}

// TestGRPCRefusals is CS-4 on gRPC.
func TestGRPCRefusals(t *testing.T) {
	v := newEnv(t)
	failing := func(code codes.Code) string {
		return v.serveGRPC(t, ligoID, &fakeService{err: status.Error(code, "refused")})
	}
	for name, tc := range map[string]struct {
		address string
		is      error
		text    string
	}{
		"another SPIFFE ID": {v.serveGRPC(t, "spiffe://prod.lab/ns/sys/sa/other", &fakeService{}), ErrUnauthorized, "unexpected ID"},
		"unauthenticated":   {failing(codes.Unauthenticated), ErrUnauthorized, "refused"},
		"permission denied": {failing(codes.PermissionDenied), ErrUnauthorized, "refused"},
		"unavailable":       {failing(codes.Unavailable), ErrUnavailable, "refused"},
		"rate limited":      {failing(codes.ResourceExhausted), ErrUnavailable, "refused"},
		"internal":          {failing(codes.Internal), nil, "unexpected answer"},
		"nobody listens":    {"127.0.0.1:1", ErrUnavailable, "connect"},
		"a bad auth": {v.serveGRPC(t, ligoID, &fakeService{bindings: []*workloadv1alpha1.WorkloadBinding{{
			Auth: mustStruct(t, map[string]any{"config": "not an object"})}}}), nil, "not a bindings document"},
	} {
		c := v.client(t, tc.address, GRPC)
		_, err := c.Bindings(t.Context(), Filter{})
		if err == nil || !strings.Contains(err.Error(), tc.text) || tc.is != nil && !errors.Is(err, tc.is) {
			t.Errorf("%s: %v", name, err)
		}
		if tc.is == nil && (errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrUnavailable)) {
			t.Errorf("%s: %v has a sentinel", name, err)
		}
		if _, err := c.Flows(t.Context(), Filter{}); err == nil && name != "a bad auth" {
			t.Errorf("%s: flows answered", name)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := v.client(t, v.serveGRPC(t, ligoID, &fakeService{}), GRPC).Bindings(ctx, Filter{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}
