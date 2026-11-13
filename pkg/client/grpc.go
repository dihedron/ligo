package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync/atomic"

	workloadv1alpha1 "github.com/dihedron/ligo/api/gen/workload/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// grpcTransport calls WorkloadBindingService.
type grpcTransport struct {
	conn    *grpc.ClientConn
	api     workloadv1alpha1.WorkloadBindingServiceClient
	refused atomic.Pointer[error] // why the last handshake refused the server; gRPC reports it only as text
}

// newGRPC dials lazily; tlsConfig builds the TLS configuration, telling
// its argument the outcome of each check of the server's identity.
func newGRPC(address string, tlsConfig func(verified func(error)) *tls.Config) (*grpcTransport, error) {
	g := &grpcTransport{}
	cfg := tlsConfig(func(err error) {
		if err != nil {
			g.refused.Store(&err)
		} else {
			g.refused.Store(nil)
		}
	})
	conn, err := grpc.NewClient("passthrough:///"+address, grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxBody)))
	if err != nil {
		return nil, err
	}
	g.conn, g.api = conn, workloadv1alpha1.NewWorkloadBindingServiceClient(conn)
	return g, nil
}

func (g *grpcTransport) close() error { return g.conn.Close() }

func (g *grpcTransport) bindings(ctx context.Context, f Filter, etag string) ([]Binding, string, bool, error) {
	resp, err := g.api.GetBindings(ctx, &workloadv1alpha1.GetBindingsRequest{TargetFilter: f.Target, PlatformTypeFilter: f.PlatformType, KnownEtag: etag})
	if err != nil {
		return nil, "", false, g.failure(ctx, err)
	}
	if resp.GetNotModified() {
		return nil, resp.GetEtag(), true, nil
	}
	items := make([]Binding, len(resp.GetItems()))
	for i, it := range resp.GetItems() {
		w := wireBinding{ID: it.GetId(), Name: it.GetName(), Source: it.GetSource(), Target: it.GetTarget(), AccessLevel: it.GetAccessLevel(),
			PlatformType: it.GetPlatformType(), Platform: it.GetPlatform(), Revision: it.GetRevision(), Spec: it.GetSpec().AsMap(),
			UpdatedAt: it.GetUpdatedAt().AsTime()}
		auth, err := it.GetAuth().MarshalJSON() // decoded as the REST body is, so both transports agree
		if err == nil {
			err = json.Unmarshal(auth, &w.Auth)
		}
		if err != nil {
			return nil, "", false, fmt.Errorf("the answer is not a bindings document: %w", err)
		}
		items[i] = w.binding()
	}
	return items, resp.GetEtag(), false, nil
}

func (g *grpcTransport) flows(ctx context.Context, f Filter, etag string) ([]BindingFlows, string, bool, error) {
	resp, err := g.api.GetFlows(ctx, &workloadv1alpha1.GetFlowsRequest{TargetFilter: f.Target, KnownEtag: etag})
	if err != nil {
		return nil, "", false, g.failure(ctx, err)
	}
	if resp.GetNotModified() {
		return nil, resp.GetEtag(), true, nil
	}
	items := make([]BindingFlows, len(resp.GetItems()))
	for i, it := range resp.GetItems() {
		b := BindingFlows{Binding: it.GetBinding(), Source: it.GetSource(), Target: it.GetTarget(), Flows: make([]Flow, len(it.GetFlows()))}
		for j, fl := range it.GetFlows() {
			ports := make([]PortRange, len(fl.GetPorts()))
			for k, p := range fl.GetPorts() {
				ports[k] = PortRange{Low: int(p.GetLow()), High: int(p.GetHigh())}
			}
			b.Flows[j] = Flow{Name: fl.GetName(), Purpose: fl.GetPurpose(), Protocol: fl.GetProtocol(), Destination: fl.GetDestination(), Ports: ports,
				TLS: fl.GetTls(), ServerName: fl.GetServerName(), Description: fl.GetDescription(), DeclaredBy: fl.GetDeclaredBy()}
		}
		items[i] = b
	}
	return items, resp.GetEtag(), false, nil
}

// failure maps a gRPC error to the client's sentinels, as REST maps
// statuses.
func (g *grpcTransport) failure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	case codes.Unavailable:
		if refused := g.refused.Load(); refused != nil {
			return *refused
		}
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	case codes.ResourceExhausted, codes.DeadlineExceeded:
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return fmt.Errorf("unexpected answer: %w", err)
}
