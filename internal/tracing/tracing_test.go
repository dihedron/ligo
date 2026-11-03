package tracing

import (
	"context"
	"testing"

	"github.com/dihedron/ligo/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
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
