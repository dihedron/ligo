package adminclient

import (
	"context"
	"errors"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

const someID = "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b"

// notYet are the operations of the OpenAPI document that have no method yet:
// the human decisions. TestEveryOperationHasAMethod fails
// when one of them gets a method, so that the list only shrinks.
var notYet = []string{
	// human decisions: never in the package by default (T-A4)
	"approveChangeRequest", "declineChangeRequest", "ratifyChangeRequest", "revertChangeRequest", "breakGlass",
}

type operation struct{ id, method, path string }

func operations(t *testing.T) []operation {
	t.Helper()
	data, err := os.ReadFile("../../api/openapi/admin.v1alpha1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var out []operation
	for path, item := range doc.Paths {
		for method, op := range item {
			if m, ok := op.(map[string]any); ok && m["operationId"] != nil {
				out = append(out, operation{m["operationId"].(string), strings.ToUpper(method), path})
			}
		}
	}
	slices.SortFunc(out, func(a, b operation) int { return strings.Compare(a.id, b.id) })
	return out
}

func exported(id string) string { return strings.ToUpper(id[:1]) + id[1:] }

// TestEveryOperationHasAMethod is AC-3, first half: the document and the
// package agree on which operations exist.
func TestEveryOperationHasAMethod(t *testing.T) {
	typ := reflect.TypeFor[*Client]()
	for _, op := range operations(t) {
		_, has := typ.MethodByName(exported(op.id))
		missing := slices.Contains(notYet, op.id)
		switch {
		case !has && !missing:
			t.Errorf("%s %s (%s) has no method %s and is not in notYet", op.method, op.path, op.id, exported(op.id))
		case has && missing:
			t.Errorf("%s has a method now: take it out of notYet", op.id)
		}
	}
	for _, id := range notYet {
		if !slices.ContainsFunc(operations(t), func(o operation) bool { return o.id == id }) {
			t.Errorf("notYet lists %s, which is not in the document", id)
		}
	}
}

// recorder is a server that answers every GET with body and remembers the
// requests.
type recorder struct {
	mu   sync.Mutex
	reqs []*http.Request
	body func(*http.Request) (int, string)
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	code, body := 200, `{"items":[]}`
	if r.body != nil {
		code, body = r.body(req)
	}
	w.Header().Set("Content-Type", "application/json")
	if code >= 400 {
		w.Header().Set("Content-Type", "application/problem+json")
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

func (r *recorder) last() *http.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reqs[len(r.reqs)-1]
}

func newClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	u, pool := serveTLS(t, h)
	c, err := New(Config{ServerURL: u, RootCAs: pool, Basic: &BasicAuth{Username: "ada", Password: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestReadsUseTheDocumentsVerbAndPath is AC-3, second half: each read method
// calls the verb and path of its operation.
func TestReadsUseTheDocumentsVerbAndPath(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{}
	c := newClient(t, rec)
	calls := map[string]func() error{
		"listSources":           func() error { return drainSeq(c.ListSources(ctx, SourceFilter{})) },
		"getSource":             func() error { _, err := c.GetSource(ctx, "x"); return err },
		"sourceAudit":           func() error { return drainSeq(c.SourceAudit(ctx, "x", 0)) },
		"listSourceBindings":    func() error { return drainSeq(c.ListSourceBindings(ctx, "x", 0)) },
		"listTargets":           func() error { return drainSeq(c.ListTargets(ctx, TargetFilter{})) },
		"getTarget":             func() error { _, err := c.GetTarget(ctx, "x"); return err },
		"targetAudit":           func() error { return drainSeq(c.TargetAudit(ctx, "x", 0)) },
		"listTargetBindings":    func() error { return drainSeq(c.ListTargetBindings(ctx, "x", 0)) },
		"listBindings":          func() error { return drainSeq(c.ListBindings(ctx, BindingFilter{})) },
		"getBinding":            func() error { _, err := c.GetBinding(ctx, "x"); return err },
		"bindingAudit":          func() error { return drainSeq(c.BindingAudit(ctx, "x", 0)) },
		"getBindingFlows":       func() error { _, err := c.GetBindingFlows(ctx, "x"); return err },
		"searchCatalog":         func() error { return drainSeq(c.SearchCatalog(ctx, CatalogFilter{})) },
		"getCatalogTarget":      func() error { _, err := c.GetCatalogTarget(ctx, "x"); return err },
		"getCatalogTargetFlows": func() error { _, err := c.GetCatalogTargetFlows(ctx, "x"); return err },
		"listCatalogSources":    func() error { return drainSeq(c.ListCatalogSources(ctx, 0)) },
		"listChangeRequests":    func() error { return drainSeq(c.ListChangeRequests(ctx, ChangeRequestFilter{})) },
		"getChangeRequest":      func() error { _, err := c.GetChangeRequest(ctx, someID); return err },
		"listAccounts":          func() error { return drainSeq(c.ListAccounts(ctx, 0)) },
		"getAccount":            func() error { _, err := c.GetAccount(ctx, "x"); return err },
		"listPlatforms":         func() error { _, err := c.ListPlatforms(ctx); return err },
		"getPlatform":           func() error { _, err := c.GetPlatform(ctx, "x"); return err },
		"platformAudit":         func() error { return drainSeq(c.PlatformAudit(ctx, "x", 0)) },
		"listIdentityProviders": func() error { _, err := c.ListIdentityProviders(ctx); return err },
		"getIdentityProvider":   func() error { _, err := c.GetIdentityProvider(ctx, "x"); return err },
		"identityProviderAudit": func() error { return drainSeq(c.IdentityProviderAudit(ctx, "x", 0)) },
		"listSecretStores":      func() error { _, err := c.ListSecretStores(ctx); return err },
		"getSecretStore":        func() error { _, err := c.GetSecretStore(ctx, "x"); return err },
		"secretStoreAudit":      func() error { return drainSeq(c.SecretStoreAudit(ctx, "x", 0)) },
	}
	for _, op := range operations(t) {
		call, ok := calls[op.id]
		if !ok {
			continue
		}
		if err := call(); err != nil {
			t.Errorf("%s: %v", op.id, err)
			continue
		}
		r := rec.last()
		want := strings.NewReplacer("{name}", "x", "{id}", someID).Replace(op.path)
		if r.Method != op.method || r.URL.Path != want {
			t.Errorf("%s calls %s %s, the document says %s %s", op.id, r.Method, r.URL.Path, op.method, want)
		}
		delete(calls, op.id)
	}
	for id := range calls {
		t.Errorf("%s is not an operation of the document", id)
	}
}

// drainSeq reads an iterator to its end and returns its first error.
func drainSeq[T any](seq func(func(T, error) bool)) error {
	var first error
	seq(func(_ T, err error) bool {
		if err != nil {
			first = err
			return false
		}
		return true
	})
	return first
}

// TestFiltersReachTheServer: the fields of a filter are the query parameters of the document.
func TestFiltersReachTheServer(t *testing.T) {
	rec := &recorder{}
	c := newClient(t, rec)
	ctx := context.Background()
	before := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	yes := true
	if err := drainSeq(c.ListBindings(ctx, BindingFilter{Source: "s", Target: "t", AccessLevel: "read", Phase: "FAILED", Jurisdiction: "dc/*",
		ExpiringBefore: &before, PropagationPending: &yes, PageSize: 500})); err != nil {
		t.Fatal(err)
	}
	q := rec.last().URL.Query()
	for k, v := range map[string]string{"source": "s", "target": "t", "accessLevel": "read", "phase": "FAILED", "jurisdiction": "dc/*",
		"expiringBefore": "2026-12-01T00:00:00Z", "propagationPending": "true", "pageSize": "200"} {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q (query %s)", k, q.Get(k), v, rec.last().URL.RawQuery)
		}
	}
	if q.Has("realm") || q.Has("pageToken") {
		t.Errorf("an empty field was sent: %s", rec.last().URL.RawQuery)
	}

	if err := drainSeq(c.ListSources(ctx, SourceFilter{State: "DEPRECATED", Label: "team=a", Q: "led"})); err != nil {
		t.Fatal(err)
	}
	if q := rec.last().URL.Query(); q.Get("state") != "DEPRECATED" || q.Get("label") != "team=a" || q.Get("q") != "led" {
		t.Errorf("sources: %s", rec.last().URL.RawQuery)
	}
	if err := drainSeq(c.SearchCatalog(ctx, CatalogFilter{IncludeDeprecated: true, ForSource: "s"})); err != nil {
		t.Fatal(err)
	}
	if q := rec.last().URL.Query(); q.Get("state") != "DEPRECATED" || q.Get("forSource") != "s" {
		t.Errorf("catalog: %s", rec.last().URL.RawQuery)
	}
	yes = true
	if err := drainSeq(c.ListChangeRequests(ctx, ChangeRequestFilter{Status: "PENDING", ResourceType: "SECRET_STORE", AwaitingMe: &yes})); err != nil {
		t.Fatal(err)
	}
	if q := rec.last().URL.Query(); q.Get("status") != "PENDING" || q.Get("resourceType") != "SECRET_STORE" || q.Get("awaitingMe") != "true" {
		t.Errorf("change requests: %s", rec.last().URL.RawQuery)
	}
	// a name is escaped
	if _, err := c.GetSource(ctx, "a b/c"); err != nil {
		t.Fatal(err)
	}
	if got := rec.last().URL.EscapedPath(); got != "/v1/admin/sources/a%20b%2Fc" {
		t.Errorf("a name with a space and a slash: %s", got)
	}
	if _, err := c.GetChangeRequest(ctx, "not-a-uuid"); err == nil {
		t.Error("a bad change request ID was accepted")
	}
}

// TestPagination is AC-4: the iterator follows nextPageToken to the end,
// stops on an error, and stops when the caller stops.
func TestPagination(t *testing.T) {
	ctx := context.Background()
	item := func(n string) string {
		return `{"id":` + n + `,"action":"A` + n + `","actor":"ada","occurredAt":"2026-11-14T10:00:00Z"}`
	}
	serve := func(failOn string) *recorder {
		return &recorder{body: func(r *http.Request) (int, string) {
			tok := r.URL.Query().Get("pageToken")
			switch {
			case tok == "":
				return 200, `{"items":[` + item("1") + `,` + item("2") + `],"nextPageToken":"p2"}`
			case failOn != "" && tok == failOn:
				return 503, `{"type":"urn:ligo:problem:unavailable","title":"x","status":503,"detail":"later"}`
			case tok == "p2":
				return 200, `{"items":[` + item("3") + `],"nextPageToken":"p3"}`
			default:
				return 200, `{"items":[` + item("4") + `],"nextPageToken":null}`
			}
		}}
	}
	actions := func(c *Client, stopAfter int) (got []string, err error) {
		for e, err2 := range c.SourceAudit(ctx, "x", 2) {
			if err2 != nil {
				return got, err2
			}
			got = append(got, e.Action)
			if len(got) == stopAfter {
				break
			}
		}
		return got, nil
	}

	rec := serve("")
	c := newClient(t, rec)
	got, err := actions(c, -1)
	if err != nil || !slices.Equal(got, []string{"A1", "A2", "A3", "A4"}) {
		t.Errorf("all pages: %v, %v", got, err)
	}
	if len(rec.reqs) != 3 || rec.reqs[0].URL.Query().Get("pageSize") != "2" {
		t.Errorf("%d requests, first %s", len(rec.reqs), rec.reqs[0].URL.RawQuery)
	}

	// the caller stops: no further page is fetched
	rec = serve("")
	c = newClient(t, rec)
	if got, _ := actions(c, 2); len(got) != 2 || len(rec.reqs) != 1 {
		t.Errorf("stopped after 2: %v, %d requests", got, len(rec.reqs))
	}
	if got, _ := actions(c, 3); len(got) != 3 || len(rec.reqs) != 3 {
		t.Errorf("stopped after 3: %v, %d requests", got, len(rec.reqs))
	}

	// an error ends the iteration, and is yielded once
	rec = serve("p3")
	c = newClient(t, rec)
	got, err = actions(c, -1)
	if !errors.Is(err, ErrUnavailable) || !slices.Equal(got, []string{"A1", "A2", "A3"}) {
		t.Errorf("an error on page 3: %v, %v", got, err)
	}

	// one page: the token comes back, for a caller that pages by hand
	rec = serve("")
	c = newClient(t, rec)
	p, err := c.SourceAuditPage(ctx, "x", 2, "")
	if err != nil || len(p.Items) != 2 || p.NextPageToken != "p2" {
		t.Errorf("a page: %+v, %v", p, err)
	}
	if u := rec.last().URL; u.Query().Has("pageToken") {
		t.Errorf("an empty token was sent: %s", u.RawQuery)
	}
}

// TestReadsDecode: what the server sends decodes into the typed resources, a
// reader's platform has no definition and a decider's has it (AC-13, reads).
func TestReadsDecode(t *testing.T) {
	ctx := context.Background()
	const reader = `{"apiVersion":"ligo.dihedron.org/v1alpha1","kind":"Platform","name":"pg","type":"postgres","realm":"prod","jurisdiction":"dc/b",
		"targetJurisdictions":["dc/b"],"allowedSourceTrustDomains":["example.org"],"networkFlows":[],"identityProvider":{"type":"spire","instance":"main"},
		"secretStore":{"type":"vault","instance":"main"},"health":{"serving":true}}`
	const decider = `{"apiVersion":"ligo.dihedron.org/v1alpha1","kind":"Platform","name":"pg","type":"postgres","realm":"prod","jurisdiction":"dc/b",
		"targetJurisdictions":["dc/b"],"allowedSourceTrustDomains":[],"networkFlows":[],"identityProvider":{"type":"spire","instance":"main"},
		"secretStore":{"type":"vault","instance":"main"},"revision":5,
		"definition":{"kind":"Platform","metadata":{"name":"pg","jurisdiction":"dc/b","realm":"prod"},"type":"postgres","rotationInterval":"24h"}}`
	body := reader
	c := newClient(t, &recorder{body: func(*http.Request) (int, string) { return 200, body }})
	p, err := c.GetPlatform(ctx, "pg")
	if err != nil || p.Name != "pg" || p.Revision != nil || p.Definition != nil || p.Health == nil || !p.Health.Serving {
		t.Errorf("a reader's platform: %+v, %v", p, err)
	}
	body = decider
	p, err = c.GetPlatform(ctx, "pg")
	if err != nil || p.Revision == nil || *p.Revision != 5 || p.Definition == nil || p.Definition.Type != "postgres" {
		t.Errorf("a decider's platform: %+v, %v", p, err)
	}

	body = `{"apiVersion":"ligo.dihedron.org/v1alpha1","kind":"Binding","metadata":{"id":"` + someID + `","name":"b","realm":"prod","sourceJurisdiction":"dc/a",
		"targetJurisdiction":"dc/b","platformJurisdiction":"dc/b","platformType":"postgres","platform":"pg","wiring":{"identityProvider":{"type":"spire","instance":"main"},
		"secretStore":{"type":"vault","instance":"main"}},"revision":4,"activeRevision":3,"createdAt":"2026-11-14T09:00:00Z","updatedAt":"2026-11-14T09:30:00Z",
		"createdBy":"ada","updatedBy":"ada"},"source":"s","target":"t","accessLevel":"read","parameters":{},"expiresAt":"2026-12-01T00:00:00Z",
		"status":{"phase":"ACTIVE","operation":"APPLY","attempt":1,"workflowId":"w","currentStep":"","message":"","lastTransitionTime":"2026-11-14T09:30:00Z",
		"pendingChangeRequestId":null,"propagationPending":false,"breakGlass":null},"requested":{"sourceRevision":1,"targetRevision":1,"trustDomain":"example.org",
		"svidRegex":"^x$","spec":{}},"active":{"revision":3,"svidRegex":"^x$","since":"2026-11-14T09:30:00Z"},"auth":{"strategy":"vault-dynamic"},"spec":{},
		"stages":[{"stage":"TARGET","providerType":"postgres","providerInstance":"pg","status":"ENSURED","revision":4,"workflowId":"w","artifact":{},"updatedAt":"2026-11-14T09:30:00Z"}],
		"audit":[]}`
	b, err := c.GetBinding(ctx, "b")
	if err != nil || b.Status.Phase != "ACTIVE" || b.Metadata.Revision != 4 || b.ExpiresAt == nil || b.ExpiresAt.Year() != 2026 || len(b.Stages) != 1 || b.Active == nil {
		t.Errorf("a binding: %+v, %v", b, err)
	}

	body = `{"networkFlows":[{"name":"data","purpose":"DATA","protocol":"TCP","destination":"db.example.org","ports":[5432,"6000-6010"],"tls":true}]}`
	fl, err := c.GetBindingFlows(ctx, "b")
	if err != nil || len(fl) != 1 || fl[0].Name != "data" || !fl[0].Tls {
		t.Errorf("flows: %+v, %v", fl, err)
	}
	body = `{}`
	if fl, err = c.GetCatalogTargetFlows(ctx, "t"); err != nil || len(fl) != 0 {
		t.Errorf("no flows: %+v, %v", fl, err)
	}

	// a body that is not what the contract says is an error that names the call, not the body
	body = `{"metadata":"oops"}`
	if _, err := c.GetSource(ctx, "s"); err == nil || !strings.Contains(err.Error(), "/v1/admin/sources/s") || strings.Contains(err.Error(), "oops") {
		t.Errorf("a malformed body: %v", err)
	}
}
