//go:build lab

package serve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	workloadv1alpha1 "github.com/dihedron/ligo/api/gen/workload/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// caller is a client of ligo's workload listener with a minted SVID
// ("workload" or "stranger") and, optionally, the workload's JWT-SVID
// instead of its certificate.
type caller struct {
	t      *testing.T
	base   string
	client *http.Client
	jwt    string
}

func newWorkload(t *testing.T, who string, jwt bool) *caller {
	t.Helper()
	w := &caller{t: t, base: e2eEnv(t, "LIGO_E2E_WORKLOAD")}
	cfg := ligoTLS(t, who)
	if jwt {
		cfg = ligoTLS(t, "")
		token, err := os.ReadFile(filepath.Join(e2eEnv(t, "LIGO_E2E_DIR"), "workload-jwt"))
		if err != nil {
			t.Fatal(err)
		}
		w.jwt = strings.TrimSpace(string(token))
	}
	w.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	return w
}

// get returns the status, the ETag and the decoded body of path.
func (w *caller) get(path, etag string) (int, string, map[string]any) {
	w.t.Helper()
	req, _ := http.NewRequest("GET", w.base+path, nil)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if w.jwt != "" {
		req.Header.Set("Authorization", "Bearer "+w.jwt)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		w.t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, resp.Header.Get("ETag"), out
}

func items(body map[string]any) []map[string]any {
	var out []map[string]any
	list, _ := body["items"].([]any)
	for _, it := range list {
		out = append(out, it.(map[string]any))
	}
	return out
}

// TestServeE2EWorkload: the e2e binding is ACTIVE; its workload receives it
// over mTLS, with a JWT-SVID and over gRPC, with the same ETags; its flows
// are the target's, the platform's, the secret store's and ligo's (AC-73);
// a workload its source does not match receives nothing.
func TestServeE2EWorkload(t *testing.T) {
	_, target, binding := names(t)
	w := newWorkload(t, "workload", false)

	code, etag, body := w.get("/v1/bindings", "")
	list := items(body)
	if code != http.StatusOK || len(list) != 1 || list[0]["name"] != binding || list[0]["target"] != target || list[0]["revision"] != float64(1) ||
		list[0]["auth"] == nil || list[0]["spec"] == nil || list[0]["platformType"] != "postgres.v1" {
		t.Fatalf("GET /v1/bindings: %d %v", code, body)
	}
	if code, _, _ := w.get("/v1/bindings", etag); code != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", code)
	}
	for path, n := range map[string]int{"/v1/bindings?target=" + target: 1, "/v1/bindings?target=nope": 0,
		"/v1/bindings?platformType=postgres.v1": 1, "/v1/bindings?platformType=oracle.v1": 0} {
		if code, _, body := w.get(path, ""); code != http.StatusOK || len(items(body)) != n {
			t.Errorf("%s: %d %v", path, code, body)
		}
	}

	code, flowsETag, body := w.get("/v1/flows?target="+target, "")
	list = items(body)
	if code != http.StatusOK || len(list) != 1 || list[0]["binding"] != binding {
		t.Fatalf("GET /v1/flows: %d %v", code, body)
	}
	var declared []string
	for _, f := range list[0]["flows"].([]any) {
		declared = append(declared, f.(map[string]any)["declaredBy"].(string))
	}
	if strings.Join(declared, " ") != "target:"+target+" platform:pg-ledger secret-store:vault-prod ligo" {
		t.Errorf("AC-73: flows declared by %v", declared)
	}
	if b, _ := json.Marshal(body); strings.Contains(string(b), `"auth"`) || strings.Contains(string(b), `"spec"`) {
		t.Errorf("AC-73: flows carry credentials: %s", b)
	}
	if code, _, _ := w.get("/v1/flows?target="+target, flowsETag); code != http.StatusNotModified {
		t.Errorf("flows If-None-Match: %d", code)
	}

	if code, jwtETag, _ := newWorkload(t, "", true).get("/v1/bindings", ""); code != http.StatusOK || jwtETag != etag {
		t.Errorf("JWT-SVID: %d %s, want the mTLS ETag %s", code, jwtETag, etag)
	}
	if code, _, body := newWorkload(t, "stranger", false).get("/v1/bindings", ""); code != http.StatusOK || len(items(body)) != 0 {
		t.Errorf("a workload the source does not match: %d %v", code, body)
	}

	conn, err := grpc.NewClient("dns:///"+strings.TrimPrefix(w.base, "https://"), grpc.WithTransportCredentials(credentials.NewTLS(ligoTLS(t, "workload"))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	g := workloadv1alpha1.NewWorkloadBindingServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := g.GetBindings(ctx, &workloadv1alpha1.GetBindingsRequest{})
	if err != nil || resp.GetEtag() != etag || len(resp.GetItems()) != 1 || resp.GetItems()[0].GetName() != binding {
		t.Errorf("gRPC GetBindings: %v %v", resp, err)
	}
	if again, err := g.GetBindings(ctx, &workloadv1alpha1.GetBindingsRequest{KnownEtag: etag}); err != nil || !again.GetNotModified() {
		t.Errorf("gRPC known ETag: %v %v", again, err)
	}
	if fr, err := g.GetFlows(ctx, &workloadv1alpha1.GetFlowsRequest{TargetFilter: target}); err != nil || fr.GetEtag() != flowsETag ||
		len(fr.GetItems()) != 1 || len(fr.GetItems()[0].GetFlows()) != 4 {
		t.Errorf("gRPC GetFlows: %v %v", fr, err)
	}
}

// revoked checks AC-12 once the binding is deleted: its workload no longer
// receives it, through LISTEN/NOTIFY.
func revoked(t *testing.T) {
	t.Helper()
	w := newWorkload(t, "workload", false)
	deadline := time.Now().Add(30 * time.Second)
	for {
		code, _, body := w.get("/v1/bindings", "")
		if code == http.StatusOK && len(items(body)) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("AC-12: the deleted binding is still served: %d %v", code, body)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
