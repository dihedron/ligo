package admin

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/client"
)

// fake is an admin API that answers canned JSON by path and records the
// requests it got.
type fake struct {
	mu       sync.Mutex
	srv      *httptest.Server
	answers  map[string][]string // path -> answers, the last one repeats
	requests []string            // "METHOD path?query"
}

func newFake(t *testing.T, answers map[string][]string) *fake {
	f := &fake{answers: answers}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		list, ok := f.answers[r.URL.Path]
		if !ok {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"type":"urn:ligo:problem:not-found","title":"Not Found","status":404,"detail":"nothing at ` + r.URL.Path + `"}`))
			return
		}
		_, _ = w.Write([]byte(list[0]))
		if len(list) > 1 {
			f.answers[r.URL.Path] = list[1:]
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// base connects to f as olivia, printing in format into out.
func (f *fake) base(t *testing.T, format string, out *bytes.Buffer) Base {
	dir := t.TempDir()
	ca, pw := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "pw")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600)
	_ = os.WriteFile(pw, []byte("pw"), 0o600)
	b := Base{Options: client.Options{ServerURL: f.srv.URL, CACert: ca, Username: "olivia", PasswordFile: pw}, out: out}
	b.SetGlobals(&client.Globals{Format: format})
	return b
}

func (f *fake) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

func fields(s string) string { return strings.Join(strings.Fields(s), " ") }

// TestReadCommands: each command asks the path and filters of §7.2.3 and
// prints its columns.
func TestReadCommands(t *testing.T) {
	binding := `{"metadata":{"name":"b1","revision":3},"source":"s1","target":"t1","accessLevel":"read","status":{"phase":"ACTIVE"},"expiresAt":null}`
	f := newFake(t, map[string][]string{
		"/v1/admin/bindings/b1":              {binding},
		"/v1/admin/bindings":                 {`{"items":[` + binding + `],"nextPageToken":null}`},
		"/v1/admin/bindings/b1/flows":        {`{"binding":"b1","networkFlows":[{"name":"db","purpose":"DATA","protocol":"TCP","destination":"pg","ports":[5432],"tls":true,"declaredBy":"target:t1"}]}`},
		"/v1/admin/platforms":                {`{"items":[{"name":"pg-ledger","type":"postgres.v1","zone":"prod","scope":"dc/x","health":{"serving":true}}]}`},
		"/v1/admin/platforms/pg-ledger":      {`{"name":"pg-ledger","uiSchemas":{"targetDefinition":{"fields":[]}}}`},
		"/v1/admin/catalog/targets":          {`{"items":[{"name":"t1","platform":"pg-ledger","platformType":"postgres.v1","scope":"dc/x","state":"ACTIVE","bound":true}]}`},
		"/v1/admin/catalog/targets/t1":       {`{"metadata":{"name":"t1"},"outcomes":[]}`},
		"/v1/admin/catalog/targets/t1/flows": {`{"target":"t1","networkFlows":[]}`},
		"/v1/admin/bindings/b1/audit":        {`{"items":[{"id":7,"occurredAt":"2026-10-30T10:00:00Z","action":"CR_APPLIED","actor":"dora"}]}`},
		"/v1/admin/audit/verify":             {`{"valid":true,"entries":12}`},
		"/v1/admin/maintenance":              {`{"maintenanceMode":true,"inFlight":1}`, `{"maintenanceMode":true,"inFlight":0}`},
		"/v1/admin/governance":               {`{"policy":{"requiredScopes":[]},"sha256":"ab"}`},
		"/v1/admin/change-requests":          {`{"items":[{"id":"c1","resourceType":"BINDING","resourceName":"b1","operation":"CREATE","kind":"STANDARD","status":"PENDING","awaitingApproval":["TARGET"],"requestedBy":"olga"}]}`},
		"/v1/admin/change-requests/c1":       {`{"id":"c1","payloadSha256":"ff"}`},
		"/v1/admin/break-glass":              {`{"items":[{"id":"open","status":"APPLIED","breakGlass":{"expiresAt":"2999-01-01T00:00:00Z"},"sides":[{"basis":"BREAK_GLASS"}]},{"id":"ratified","status":"APPLIED","breakGlass":{"expiresAt":"2999-01-01T00:00:00Z"},"sides":[{"basis":"BREAK_GLASS","ratifiedBy":"dora"}]}]}`},
	})
	var out bytes.Buffer
	b := f.base(t, "table", &out)
	drainPoll = 10 * time.Millisecond
	for _, tc := range []struct {
		name    string
		run     func([]string) error
		request string
		output  []string
	}{
		{"get", (&Get{Base: b, Args: ResourceArgs{"binding", "b1"}}).Execute, "GET /v1/admin/bindings/b1", []string{"b1 s1 t1 read ACTIVE 3 -"}},
		{"list", (&List{Base: b, Page: Page{PageSize: 10}, Phase: "ACTIVE", Scope: "dc/*", Args: struct {
			Kind string `positional-arg-name:"kind" choice:"sources" choice:"targets" choice:"bindings" description:"Resource kind."`
		}{"bindings"}}).Execute, "GET /v1/admin/bindings?pageSize=10&phase=ACTIVE&scope=dc%2F%2A", []string{"NAME SOURCE TARGET", "b1 s1 t1"}},
		{"flows", (&Flows{Base: b, Args: struct {
			Binding string `positional-arg-name:"binding" description:"Binding name."`
		}{"b1"}}).Execute, "GET /v1/admin/bindings/b1/flows", []string{"db DATA TCP pg 5432 true target:t1"}},
		{"platform list", (&PlatformList{Base: b}).Execute, "GET /v1/admin/platforms", []string{"pg-ledger postgres.v1 prod dc/x true"}},
		{"platform schema", (&PlatformSchema{Base: b, Args: NameArg{"pg-ledger"}}).Execute, "GET /v1/admin/platforms/pg-ledger", []string{"targetDefinition:"}},
		{"catalog search", (&CatalogSearch{Base: b, Query: "led", ForSource: "s1", Label: []string{"team=fin"}}).Execute,
			"GET /v1/admin/catalog/targets?forSource=s1&label=team%3Dfin&q=led", []string{"t1 pg-ledger postgres.v1 dc/x ACTIVE true"}},
		{"catalog show", (&CatalogShow{Base: b, Args: NameArg{"t1"}}).Execute, "GET /v1/admin/catalog/targets/t1", []string{"name: t1"}},
		{"catalog flows", (&CatalogFlows{Base: b, Args: NameArg{"t1"}}).Execute, "GET /v1/admin/catalog/targets/t1/flows", []string{"NAME PURPOSE"}},
		{"audit list", (&AuditList{Base: b, Args: ResourceArgs{"binding", "b1"}}).Execute, "GET /v1/admin/bindings/b1/audit", []string{"7 2026-10-30T10:00:00Z CR_APPLIED dora -"}},
		{"audit verify", (&AuditVerify{Base: b}).Execute, "GET /v1/admin/audit/verify", []string{"true 12 -"}},
		{"maintenance status --wait-drained", (&MaintenanceStatus{Base: b, WaitDrained: true}).Execute, "GET /v1/admin/maintenance", []string{"true - - - 0 -"}},
		{"governance show", (&GovernanceShow{Base: b}).Execute, "GET /v1/admin/governance", []string{"sha256: ab"}},
		{"cr list", (&ChangeRequestList{Base: b, AwaitingMe: true, Kind: "binding"}).Execute,
			"GET /v1/admin/change-requests?awaitingMe=true&resourceType=BINDING", []string{"c1 BINDING b1 CREATE STANDARD PENDING TARGET olga"}},
		{"cr get", (&ChangeRequestGet{Base: b, Args: struct {
			ID string `positional-arg-name:"cr-id" description:"Change request UUID."`
		}{"c1"}}).Execute, "GET /v1/admin/change-requests/c1", []string{"payloadSha256: ff"}},
		{"break-glass list --open", (&BreakGlassList{Base: b, Open: true}).Execute, "GET /v1/admin/break-glass", []string{"open"}},
	} {
		out.Reset()
		if err := tc.run(nil); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := f.last(); got != tc.request {
			t.Errorf("%s: asked %q, want %q", tc.name, got, tc.request)
		}
		for _, want := range tc.output {
			if !strings.Contains(fields(out.String()), want) {
				t.Errorf("%s: output lacks %q:\n%s", tc.name, want, out.String())
			}
		}
		if tc.name == "break-glass list --open" && strings.Contains(out.String(), "ratified") {
			t.Errorf("break-glass --open lists a ratified change:\n%s", out.String())
		}
	}

	out.Reset()
	j := f.base(t, "json", &out)
	if err := (&Get{Base: j, Args: ResourceArgs{"binding", "b1"}}).Execute(nil); err != nil || !strings.Contains(out.String(), `"accessLevel": "read"`) {
		t.Errorf("json: %v %s", err, out.String())
	}
	if err := (&Get{Base: b, Args: ResourceArgs{"source", "nope"}}).Execute(nil); err == nil || err.Error() != "404 not-found: nothing at /v1/admin/sources/nope" {
		t.Errorf("a problem: %v", err)
	}
}
