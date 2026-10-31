package workloadhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/resolution"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// fakeCache serves fixed bindings and target flows, and records the
// filters it was asked for.
type fakeCache struct {
	list          []resolution.Binding
	targets       map[uuid.UUID][]flows.Flow
	err           error
	target, ptype string
}

func (f *fakeCache) Resolve(_ spiffeid.ID, target, platformType string) ([]resolution.Binding, error) {
	f.target, f.ptype = target, platformType
	return f.list, f.err
}

func (f *fakeCache) TargetFlows(context.Context, []uuid.UUID) (map[uuid.UUID][]flows.Flow, error) {
	return f.targets, nil
}

func flow(name, purpose, dest string, port int) flows.Flow {
	return flows.Flow{Name: name, Purpose: purpose, Protocol: "TCP", Destination: dest, Ports: []flows.Port{{Low: port, High: port}}, TLS: true}
}

func apiSetup(t *testing.T) (*env, *fakeCache, *http.Client) {
	t.Helper()
	v := setup(t, config.AuthX509SVID)
	v.s.Listener.RateLimit.Burst = 100
	id := uuid.NewV7()
	f := &fakeCache{
		list: []resolution.Binding{{Row: resolution.Row{ID: id, Name: "workers-ledger", PlatformType: "oracle.v1", Platform: "oracle-prod",
			TargetName: "ledger-schema", SourceName: "workers", AccessLevel: "write", ActiveRevision: 4, AuthConfig: []byte(`{"secretStoreInstance": "vault-prod"}`),
			Spec: []byte(`{"host": "ledger-db"}`), SecretStoreInstance: "vault-prod", UpdatedAt: time.Date(2026, 10, 16, 7, 2, 11, 0, time.UTC)}}},
		targets: map[uuid.UUID][]flows.Flow{id: {flow("listener", "DATA", "ledger-db.prod.internal", 1522), flow("outside", "DATA", "elsewhere.internal", 22)}},
	}
	allow, err := flows.ParseAllowlist([]string{"ledger-db.prod.internal:1522"})
	if err != nil {
		t.Fatal(err)
	}
	v.s.Cache = f
	v.s.Rules = &bindings.Rules{Allow: map[string]flows.Allowlist{"oracle-prod": allow},
		PlatformFlows: map[string][]flows.Flow{"oracle-prod": {flow("scan", "DATA", "ora-scan.prod.internal", 1521)}},
		StoreFlows:    map[string][]flows.Flow{"vault-prod": {flow("vault", "CREDENTIALS", "vault.prod.internal", 8200)}},
		Ligo:          flows.LigoFlow("ligo.prod.internal", 8443, "ligo.prod.internal")}
	v.srv.Config.Handler = v.s.Handler()
	return v, f, v.client(certificate(t, v.ca, worker))
}

func (v *env) fetch(t *testing.T, c *http.Client, path, etag string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", v.srv.URL+path, nil)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// TestGetBindings: the §3.6 body in canonical JSON, its ETag, 304 for a
// matching If-None-Match, the filters, and 503 while the cache is stale.
func TestGetBindings(t *testing.T) {
	v, f, c := apiSetup(t)
	resp, body := v.fetch(t, c, "/v1/bindings?target=ledger-schema&platformType=oracle.v1", "")
	id := f.list[0].ID.String()
	want := `{"callerSpiffeId":"` + worker + `","items":[{"accessLevel":"write","auth":{"secretStoreInstance":"vault-prod"},"id":"` + id +
		`","name":"workers-ledger","platform":"oracle-prod","platformType":"oracle.v1","revision":4,"source":"workers","spec":{"host":"ledger-db"},` +
		`"target":"ledger-schema","updatedAt":"2026-10-16T07:02:11Z"}]}`
	sum := sha256.Sum256([]byte(body))
	if resp.StatusCode != 200 || body != want || resp.Header.Get("ETag") != `"sha256:`+hex.EncodeToString(sum[:])+`"` ||
		resp.Header.Get("Cache-Control") != "private, no-store" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("get: %d %v\n%s", resp.StatusCode, resp.Header, body)
	}
	if f.target != "ledger-schema" || f.ptype != "oracle.v1" {
		t.Errorf("filters: %q %q", f.target, f.ptype)
	}
	if again, body := v.fetch(t, c, "/v1/bindings", resp.Header.Get("ETag")); again.StatusCode != 304 || body != "" {
		t.Errorf("If-None-Match: %d %q", again.StatusCode, body)
	}
	if other, _ := v.fetch(t, c, "/v1/bindings", `"sha256:00"`); other.StatusCode != 200 {
		t.Errorf("another ETag: %d", other.StatusCode)
	}
	f.list = nil
	if _, body := v.fetch(t, c, "/v1/bindings", ""); body != `{"callerSpiffeId":"`+worker+`","items":[]}` {
		t.Errorf("no bindings: %s", body)
	}
	f.err = resolution.ErrStale
	if stale, _ := v.fetch(t, c, "/v1/bindings", ""); stale.StatusCode != 503 || stale.Header.Get("Retry-After") == "" {
		t.Errorf("stale: %d", stale.StatusCode)
	}
}

// TestGetFlows: the target's flows within the platform's allowed endpoints,
// then the platform's, the secret store's and ligo's; no credentials (§3.6).
func TestGetFlows(t *testing.T) {
	v, f, c := apiSetup(t)
	resp, body := v.fetch(t, c, "/v1/flows?target=ledger-schema", "")
	var doc struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil || resp.StatusCode != 200 || len(doc.Items) != 1 {
		t.Fatalf("flows: %d %s", resp.StatusCode, body)
	}
	var got []string
	for _, fl := range doc.Items[0]["flows"].([]any) {
		m := fl.(map[string]any)
		got = append(got, m["name"].(string)+"/"+m["declaredBy"].(string))
	}
	if strings.Join(got, " ") != "listener/target:ledger-schema scan/platform:oracle-prod vault/secret-store:vault-prod ligo-workload-api/ligo" {
		t.Errorf("flows: %v", got)
	}
	if doc.Items[0]["binding"] != "workers-ledger" || strings.Contains(body, `"auth"`) || strings.Contains(body, `"spec"`) || f.target != "ledger-schema" {
		t.Errorf("flows body: %s", body)
	}
	if again, _ := v.fetch(t, c, "/v1/flows?target=ledger-schema", resp.Header.Get("ETag")); again.StatusCode != 304 {
		t.Errorf("If-None-Match: %d", again.StatusCode)
	}
}
