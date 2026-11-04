package tracing

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/config"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// TestSetup: without an endpoint, tracing stays off but the W3C trace
// context is propagated; a provider names the service and the replica and
// samples by ratio, following the parent.
func TestSetup(t *testing.T) {
	stop, err := Setup(context.Background(), config.Tracing{}, "0.1.0", "ligo-a")
	if err != nil || stop(context.Background()) != nil {
		t.Fatal(err)
	}
	if _, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		t.Error("an SDK provider without an endpoint")
	}
	carrier := propagation.MapCarrier{}
	rec := tracetest.NewSpanRecorder()
	p := Provider(rec, 1, "0.1.0", "ligo-a")
	ctx, span := p.Tracer(name).Start(context.Background(), "x")
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	span.End()
	if carrier.Get("traceparent") == "" {
		t.Error("no traceparent propagated")
	}
	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("%d spans", len(ended))
	}
	attrs := map[string]string{}
	for _, a := range ended[0].Resource().Attributes() {
		attrs[string(a.Key)] = a.Value.String()
	}
	if attrs["service.name"] != "ligo" || attrs["service.version"] != "0.1.0" || attrs["service.instance.id"] != "ligo-a" {
		t.Errorf("resource %v", attrs)
	}
	// ratio 0 samples nothing new, but a sampled parent's children are kept
	none := Provider(rec, 0, "", "")
	_, root := none.Tracer(name).Start(context.Background(), "root")
	if root.SpanContext().IsSampled() {
		t.Error("ratio 0 sampled a root span")
	}
	_, child := none.Tracer(name).Start(ctx, "child")
	if !child.SpanContext().IsSampled() {
		t.Error("a sampled parent's child was dropped")
	}
}

// collector is the part of an OTLP collector the tests need: it counts the
// spans it receives.
type collector struct {
	coltrace.UnimplementedTraceServiceServer
	spans atomic.Int64
}

func (c *collector) Export(_ context.Context, r *coltrace.ExportTraceServiceRequest) (*coltrace.ExportTraceServiceResponse, error) {
	for _, rs := range r.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			c.spans.Add(int64(len(ss.GetSpans())))
		}
	}
	return &coltrace.ExportTraceServiceResponse{}, nil
}

// TestSetupTLS: a collector on a private CA receives the spans when
// ca_cert_file holds that CA, and none otherwise; a file that is missing or
// holds no certificate stops the setup.
func TestSetupTLS(t *testing.T) {
	before := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(before) })
	issuer := httptest.NewUnstartedServer(nil) // only for its certificate, valid for 127.0.0.1
	issuer.StartTLS()
	t.Cleanup(issuer.Close)
	cert := issuer.TLS.Certificates[0]
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	col := &collector{}
	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	coltrace.RegisterTraceServiceServer(srv, col)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	export := func(cfg config.Tracing) int64 {
		t.Helper()
		ratio := 1.0
		cfg.OTLPEndpoint, cfg.SampleRatio = lis.Addr().String(), &ratio
		col.spans.Store(0)
		stop, err := Setup(context.Background(), cfg, "", "")
		if err != nil {
			t.Fatal(err)
		}
		_, span := Tracer().Start(context.Background(), "x")
		span.End()
		flush, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = stop(flush) // an export refused for its certificate is what the test looks at
		return col.spans.Load()
	}
	if n := export(config.Tracing{CACertFile: ca}); n != 1 {
		t.Errorf("with the CA: %d spans, want 1", n)
	}
	if n := export(config.Tracing{}); n != 0 {
		t.Errorf("with the system roots: %d spans, want 0", n)
	}

	empty := filepath.Join(dir, "empty.crt")
	if err := os.WriteFile(empty, []byte("no certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{filepath.Join(dir, "missing.crt"), empty} {
		if _, err := Setup(context.Background(), config.Tracing{OTLPEndpoint: "localhost:1", CACertFile: file}, "", ""); err == nil {
			t.Errorf("%s: no error", file)
		}
	}
}

// TestHandlers: an RPC's spans, the client's and the server's, have an
// error status without the error's text, which may hold a plugin's details
// (§10.1: no secrets in spans); the gRPC code stays.
func TestHandlers(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p := otelgrpc.WithTracerProvider(Provider(rec, 1, "", ""))
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer(grpc.StatsHandler(ServerHandler(p)))
	healthpb.RegisterHealthServer(srv, failing{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///x",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(ClientHandler(p)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, err = healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("the caller must keep the error: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(rec.Ended()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	ended := rec.Ended()
	if len(ended) != 2 {
		t.Fatalf("%d spans", len(ended))
	}
	for _, s := range ended {
		if s.Status().Code != otelcodes.Error || s.Status().Description != "" {
			t.Errorf("%s: status %+v", s.Name(), s.Status())
		}
		if strings.Contains(fmt.Sprint(s.Attributes(), s.Events()), "s3cr3t") {
			t.Errorf("%s: the error's text in %v %v", s.Name(), s.Attributes(), s.Events())
		}
	}
}

// failing refuses with a text that must stay out of the spans.
type failing struct {
	healthpb.UnimplementedHealthServer
}

func (failing) Check(context.Context, *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return nil, status.Error(codes.Unavailable, "IDENTIFIED BY s3cr3t")
}
