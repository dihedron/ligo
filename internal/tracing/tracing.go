// Package tracing sets up ligo's OpenTelemetry traces (§10.1): spans for
// the HTTP and gRPC handlers, each workflow and step, and each plugin RPC,
// exported over OTLP/gRPC when observability.tracing.otlp_endpoint is set.
// The trace context is always propagated (W3C traceparent), to plugins too.
package tracing

import (
	"context"
	"fmt"

	"github.com/dihedron/ligo/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// name is the instrumentation scope of ligo's own spans.
const name = "github.com/dihedron/ligo"

// Tracer starts ligo's own spans (workflows and steps).
func Tracer() trace.Tracer { return otel.Tracer(name) }

// Setup installs the W3C propagator and, when an endpoint is configured,
// a provider exporting to it; it returns the function that flushes and
// stops the export. Without an endpoint the global provider stays the
// no-op one: spans cost nothing and go nowhere.
func Setup(ctx context.Context, cfg config.Tracing, version, instance string) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if cfg.OTLPEndpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("tracing: OTLP exporter: %w", err)
	}
	ratio := 0.1
	if cfg.SampleRatio != nil {
		ratio = *cfg.SampleRatio
	}
	provider := Provider(sdktrace.NewBatchSpanProcessor(exporter), ratio, version, instance)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

// Provider is ligo's tracer provider over processor: parent-based sampling
// at ratio, and the resource naming the service and this replica.
func Provider(processor sdktrace.SpanProcessor, ratio float64, version, instance string) *sdktrace.TracerProvider {
	return sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(processor),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", "ligo"),
			attribute.String("service.version", version), attribute.String("service.instance.id", instance))))
}
