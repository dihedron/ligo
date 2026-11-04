//go:build lab

package serve

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestServeTraceFailed: a binding whose target refuses its GRANT fails, with
// lab.sh serve test-otel having renamed the role.
func TestServeTraceFailed(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	dora.base = e2eEnv(t, "LIGO_E2E_ADMIN2")
	source, target, binding := names(t)
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	code, filed := olga.do("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": source + "-f"},
		"identity": map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/e2e/sa/f` + x + `$`,
			"sampleSpiffeIds": []string{"spiffe://prod.lab/ns/e2e/sa/f" + x}}, "visibility": map[string]string{"mode": "PRIVATE"}})
	if code != http.StatusAccepted {
		t.Fatalf("source: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	code, filed = olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding + "-f", "source": source + "-f", "target": target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		t.Fatalf("binding: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	phase(t, olga, binding+"-f", "FAILED")
}

// otlpFile is the part of the collector's JSON lines the test reads.
type otlpFile struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []otlpAttr `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Spans []otlpSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type otlpAttr struct {
	Key   string `json:"key"`
	Value struct {
		StringValue string `json:"stringValue"`
	} `json:"value"`
}

type otlpSpan struct {
	TraceID      string     `json:"traceId"`
	SpanID       string     `json:"spanId"`
	ParentSpanID string     `json:"parentSpanId"`
	Name         string     `json:"name"`
	Attributes   []otlpAttr `json:"attributes"`
	Status       struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
	instance string
}

func attr(attrs []otlpAttr, key string) string {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value.StringValue
		}
	}
	return ""
}

// TestServeTraceFile: every kind of span of §10.1, from both replicas, sits
// in the caller's trace, a workflow under the request that started it, a step
// under its workflow, a plugin RPC under its step; the failed ones have an
// error status without text; no secret appears anywhere in the file.
func TestServeTraceFile(t *testing.T) {
	trace, other := e2eEnv(t, "LIGO_E2E_TRACE"), strings.TrimSuffix(strings.TrimPrefix(e2eEnv(t, "LIGO_E2E_ADMIN2"), "https://"), ".ligo.lab:9443")
	path := filepath.Join(e2eEnv(t, "LIGO_E2E_DIR"), "traces.jsonl")
	data, err := os.ReadFile(path) //nolint:gosec // written by lab.sh
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{e2eEnv(t, "LIGO_TEST_LDAP_OLIVIA_PASS"), "the target database refused", "does not exist", "Basic "} {
		if strings.Contains(string(data), secret) {
			t.Errorf("the traces hold %q", secret)
		}
	}
	var spans []otlpSpan
	lines := bufio.NewScanner(strings.NewReader(string(data)))
	lines.Buffer(nil, 64<<20)
	for lines.Scan() {
		var f otlpFile
		if err := json.Unmarshal(lines.Bytes(), &f); err != nil {
			t.Fatal(err)
		}
		for _, rs := range f.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					if s.TraceID == trace {
						s.instance = attr(rs.Resource.Attributes, "service.instance.id")
						spans = append(spans, s)
					}
				}
			}
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	if len(spans) == 0 {
		t.Fatalf("no span of trace %s in %d bytes", trace, len(data))
	}
	byID := map[string]otlpSpan{}
	instances := map[string]bool{}
	for _, s := range spans {
		byID[s.SpanID] = s
		if s.Name == "admin POST" {
			instances[s.instance] = true
		}
	}
	if !instances["ligo1"] || !instances[other] {
		t.Errorf("requests traced on %v, want ligo1 and %s", instances, other)
	}
	var workflows, steps, rpcs, failedSteps, failedRPCs int
	for _, s := range spans {
		parent := byID[s.ParentSpanID]
		switch {
		case s.Name == "workflow APPLY":
			workflows++
			if s.instance != other || parent.Name != "admin POST" || parent.instance != other {
				t.Errorf("workflow on %s under %q, want %s under the approval", s.instance, parent.Name, other)
			}
			if attr(s.Attributes, "ligo.binding_id") == "" || attr(s.Attributes, "ligo.binding") == "" || attr(s.Attributes, "ligo.workflow_id") == "" {
				t.Errorf("workflow attributes %v", s.Attributes)
			}
		case strings.HasPrefix(s.Name, "step "):
			steps++
			if parent.Name != "workflow APPLY" || attr(s.Attributes, "ligo.stage") == "" || attr(s.Attributes, "ligo.provider_type") == "" {
				t.Errorf("%s under %q, attributes %v", s.Name, parent.Name, s.Attributes)
			}
			if s.Status.Code == 2 {
				failedSteps++
			}
		case strings.Contains(s.Name, "/EnsureTarget"):
			rpcs++
			if parent.Name != "step TARGET" {
				t.Errorf("%s under %q", s.Name, parent.Name)
			}
			if s.Status.Code == 2 {
				failedRPCs++
			}
		}
		if s.Status.Message != "" {
			t.Errorf("%s: status text %q", s.Name, s.Status.Message)
		}
	}
	if workflows < 2 || steps == 0 || rpcs == 0 || failedSteps == 0 || failedRPCs == 0 {
		names := []string{}
		for _, s := range spans {
			names = append(names, s.Name)
		}
		slices.Sort(names)
		t.Errorf("%d workflows, %d steps (%d failed), %d EnsureTarget (%d failed); spans %v", workflows, steps, failedSteps, rpcs, failedRPCs, slices.Compact(names))
	}
}
