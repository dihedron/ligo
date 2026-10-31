package workloadhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	workloadv1alpha1 "github.com/dihedron/ligo/api/gen/workload/v1alpha1"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/resolution"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// isGRPC reports whether r is a gRPC call, routed to the gRPC server after
// TLS termination (§7.1).
func isGRPC(r *http.Request) bool {
	return r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

// grpcError answers a gRPC call that never reaches the gRPC server with a
// trailers-only response: grpc-go would map HTTP 429 to UNAVAILABLE, not
// RESOURCE_EXHAUSTED.
func grpcError(w http.ResponseWriter, code codes.Code, msg string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", strconv.Itoa(int(code)))
	w.Header().Set("Grpc-Message", msg)
	w.WriteHeader(http.StatusOK)
}

// grpcServer serves WorkloadBindingService behind the middleware, which has
// authenticated the caller and applied its rate limit.
func (s *Server) grpcServer() *grpc.Server {
	g := grpc.NewServer()
	workloadv1alpha1.RegisterWorkloadBindingServiceServer(g, &service{s: s})
	return g
}

type service struct {
	workloadv1alpha1.UnimplementedWorkloadBindingServiceServer
	s *Server
}

// failure maps a resolution error to UNAVAILABLE, as REST answers 503.
func (v *service) failure(ctx context.Context, err error) error {
	if !errors.Is(err, resolution.ErrStale) {
		v.s.Logger.Error("resolution", "request_id", requestID(ctx), "caller", caller(ctx).String(), "error", err)
	}
	return status.Error(codes.Unavailable, "bindings cannot be resolved now")
}

// GetBindings is GET /v1/bindings, with the same ETag (§7.1).
func (v *service) GetBindings(ctx context.Context, req *workloadv1alpha1.GetBindingsRequest) (*workloadv1alpha1.GetBindingsResponse, error) {
	doc, list, err := v.s.Bindings(caller(ctx), req.GetTargetFilter(), req.GetPlatformTypeFilter())
	if err != nil {
		return nil, v.failure(ctx, err)
	}
	v.s.logResolution(ctx, workloadv1alpha1.WorkloadBindingService_GetBindings_FullMethodName, list, doc.ETag)
	resp := &workloadv1alpha1.GetBindingsResponse{Etag: doc.ETag, CallerSpiffeId: doc.Caller}
	if req.GetKnownEtag() == doc.ETag {
		resp.NotModified = true
		return resp, nil
	}
	for _, it := range doc.Items {
		auth, err := toStruct(it.Auth)
		if err != nil {
			return nil, v.failure(ctx, err)
		}
		spec, err := toStruct(it.Spec)
		if err != nil {
			return nil, v.failure(ctx, err)
		}
		resp.Items = append(resp.Items, &workloadv1alpha1.WorkloadBinding{Id: it.ID, Name: it.Name, Source: it.Source, Target: it.Target,
			AccessLevel: it.AccessLevel, PlatformType: it.PlatformType, Platform: it.Platform, Revision: it.Revision, Auth: auth, Spec: spec,
			UpdatedAt: timestamppb.New(it.UpdatedAt)})
	}
	return resp, nil
}

// GetFlows is GET /v1/flows, with the same ETag (§7.1).
func (v *service) GetFlows(ctx context.Context, req *workloadv1alpha1.GetFlowsRequest) (*workloadv1alpha1.GetFlowsResponse, error) {
	doc, list, err := v.s.Flows(ctx, caller(ctx), req.GetTargetFilter())
	if err != nil {
		return nil, v.failure(ctx, err)
	}
	v.s.logResolution(ctx, workloadv1alpha1.WorkloadBindingService_GetFlows_FullMethodName, list, doc.ETag)
	resp := &workloadv1alpha1.GetFlowsResponse{Etag: doc.ETag, CallerSpiffeId: doc.Caller}
	if req.GetKnownEtag() == doc.ETag {
		resp.NotModified = true
		return resp, nil
	}
	for _, it := range doc.Items {
		b := &workloadv1alpha1.BindingFlows{Binding: it.Binding, Source: it.Source, Target: it.Target}
		for _, f := range it.Flows {
			b.Flows = append(b.Flows, toFlow(f))
		}
		resp.Items = append(resp.Items, b)
	}
	return resp, nil
}

func toStruct(raw json.RawMessage) (*structpb.Struct, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return structpb.NewStruct(m)
}

func toFlow(f flows.Flow) *workloadv1alpha1.NetworkFlow {
	nf := &workloadv1alpha1.NetworkFlow{Name: f.Name, Purpose: f.Purpose, Protocol: f.Protocol, Destination: f.Destination, Tls: f.TLS,
		ServerName: f.ServerName, Description: f.Description, DeclaredBy: f.DeclaredBy}
	for _, p := range f.Ports {
		nf.Ports = append(nf.Ports, &workloadv1alpha1.PortRange{Low: uint32(p.Low), High: uint32(p.High)}) //nolint:gosec // ports are 1..65535 (§3.3)
	}
	return nf
}
