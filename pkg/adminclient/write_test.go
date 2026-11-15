package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const filedBody = `{"changeRequest":{"id":"` + someID + `","resourceType":"SOURCE","resourceName":"s","resourceId":null,"operation":"CREATE","kind":"STANDARD","consent":"ALL",
	"status":"PENDING","dependsOn":null,"policySha256":"ab","distinctApproversRequired":false,"payloadSha256":"cd","requestedBy":"ada",
	"requestedAt":"2026-11-14T10:00:00Z","expiresAt":"2026-11-15T10:00:00Z","sides":[],"awaitingApproval":["SOURCE"]},"resource":null}`

// writeServer answers every write with a filed change request and keeps the
// method, path, query and body of each.
type writeServer struct {
	recorder
	mu2    sync.Mutex
	bodies []string
}

func newWriteServer(t *testing.T) (*Client, *writeServer) {
	t.Helper()
	ws := &writeServer{}
	ws.body = func(r *http.Request) (int, string) {
		b, _ := io.ReadAll(r.Body)
		ws.mu2.Lock()
		ws.bodies = append(ws.bodies, string(b))
		ws.mu2.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/accounts"):
			return 201, `{"name":"ops","status":"ACTIVE","registeredBy":"ada","registeredAt":"2026-11-14T10:00:00Z"}`
		case strings.Contains(r.URL.Path, "/accounts/"):
			return 200, `{"name":"ops","status":"RETIRED","registeredBy":"ada","registeredAt":"2026-11-14T10:00:00Z"}`
		}
		return 202, filedBody
	}
	return newClient(t, ws), ws
}

func (ws *writeServer) requests() int {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return len(ws.reqs)
}

func (ws *writeServer) lastBody(t *testing.T) map[string]any {
	t.Helper()
	ws.mu2.Lock()
	defer ws.mu2.Unlock()
	var m map[string]any
	if err := json.Unmarshal([]byte(ws.bodies[len(ws.bodies)-1]), &m); err != nil {
		t.Fatalf("the body is not JSON: %q", ws.bodies[len(ws.bodies)-1])
	}
	return m
}

func someSource() SourceSpec {
	var s SourceSpec
	s.Metadata.Name = "s"
	s.Identity.TrustDomain, s.Identity.SvidRegex = "example.org", "^spiffe://example.org/ns/a/sa/.*$"
	return s
}

func someTarget() TargetSpec {
	var s TargetSpec
	s.Metadata.Name, s.Metadata.Platform = "t", "pg"
	s.Definition = map[string]any{"database": "orders"}
	s.AccessLevels = []AccessLevel{{Name: "read", Grants: map[string]any{"privileges": []string{"SELECT"}}}}
	return s
}

func someBinding() BindingSpec {
	return BindingSpec{Name: "b", Source: "s", Target: "t", AccessLevel: "read"}
}

func definition(t *testing.T, kind string) Definition {
	t.Helper()
	var d Definition
	if err := json.Unmarshal([]byte(`{"kind":"`+kind+`","metadata":{"name":"n","jurisdiction":"dc/b","realm":"prod"},"type":"x","config":{"a":1}}`), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// writes is every write method with the verb and path it must call; rev is
// whether it needs the revision of what it changes.
func writes(c *Client, t *testing.T) []struct {
	op, method, path string
	revision         bool
	call             func(rev int64) error
} {
	ctx := context.Background()
	o := Options{}
	type w = struct {
		op, method, path string
		revision         bool
		call             func(rev int64) error
	}
	cr := func(fn func(rev int64) (ChangeRequest, error)) func(int64) error {
		return func(rev int64) error { _, err := fn(rev); return err }
	}
	return []w{
		{"createSource", "POST", "/v1/admin/sources", false, cr(func(int64) (ChangeRequest, error) { return c.CreateSource(ctx, someSource(), o) })},
		{"updateSource", "PUT", "/v1/admin/sources/x", true, cr(func(r int64) (ChangeRequest, error) { return c.UpdateSource(ctx, "x", someSource(), r, o) })},
		{"deprecateSource", "POST", "/v1/admin/sources/x/deprecate", true, cr(func(r int64) (ChangeRequest, error) { return c.DeprecateSource(ctx, "x", r, o) })},
		{"reactivateSource", "POST", "/v1/admin/sources/x/reactivate", true, cr(func(r int64) (ChangeRequest, error) { return c.ReactivateSource(ctx, "x", r, o) })},
		{"retireSource", "POST", "/v1/admin/sources/x/retire", true, cr(func(r int64) (ChangeRequest, error) { return c.RetireSource(ctx, "x", r, o) })},
		{"createTarget", "POST", "/v1/admin/targets", false, cr(func(int64) (ChangeRequest, error) { return c.CreateTarget(ctx, someTarget(), o) })},
		{"updateTarget", "PUT", "/v1/admin/targets/x", true, cr(func(r int64) (ChangeRequest, error) { return c.UpdateTarget(ctx, "x", someTarget(), r, o) })},
		{"deprecateTarget", "POST", "/v1/admin/targets/x/deprecate", true, cr(func(r int64) (ChangeRequest, error) { return c.DeprecateTarget(ctx, "x", r, o) })},
		{"reactivateTarget", "POST", "/v1/admin/targets/x/reactivate", true, cr(func(r int64) (ChangeRequest, error) { return c.ReactivateTarget(ctx, "x", r, o) })},
		{"retireTarget", "POST", "/v1/admin/targets/x/retire", true, cr(func(r int64) (ChangeRequest, error) { return c.RetireTarget(ctx, "x", r, o) })},
		{"deprecateAccessLevel", "POST", "/v1/admin/targets/x/access-levels/write/deprecate", true, cr(func(r int64) (ChangeRequest, error) { return c.DeprecateAccessLevel(ctx, "x", "write", r, o) })},
		{"reactivateAccessLevel", "POST", "/v1/admin/targets/x/access-levels/write/reactivate", true, cr(func(r int64) (ChangeRequest, error) { return c.ReactivateAccessLevel(ctx, "x", "write", r, o) })},
		{"retireAccessLevel", "POST", "/v1/admin/targets/x/access-levels/write/retire", true, cr(func(r int64) (ChangeRequest, error) { return c.RetireAccessLevel(ctx, "x", "write", r, o) })},
		{"createBinding", "POST", "/v1/admin/bindings", false, cr(func(int64) (ChangeRequest, error) { return c.CreateBinding(ctx, someBinding(), false, o) })},
		{"updateBinding", "PUT", "/v1/admin/bindings/x", true, cr(func(r int64) (ChangeRequest, error) { return c.UpdateBinding(ctx, "x", someBinding(), r, o) })},
		{"deleteBinding", "DELETE", "/v1/admin/bindings/x", true, cr(func(r int64) (ChangeRequest, error) { return c.DeleteBinding(ctx, "x", r, o) })},
		{"createPlatform", "POST", "/v1/admin/platforms", false, cr(func(int64) (ChangeRequest, error) { return c.CreatePlatform(ctx, definition(t, "Platform"), o) })},
		{"updatePlatform", "PUT", "/v1/admin/platforms/x", true, cr(func(r int64) (ChangeRequest, error) {
			return c.UpdatePlatform(ctx, "x", definition(t, "Platform"), r, o)
		})},
		{"retirePlatform", "DELETE", "/v1/admin/platforms/x", true, cr(func(r int64) (ChangeRequest, error) { return c.RetirePlatform(ctx, "x", r, o) })},
		{"createIdentityProvider", "POST", "/v1/admin/identity-providers", false, cr(func(int64) (ChangeRequest, error) {
			return c.CreateIdentityProvider(ctx, definition(t, "IdentityProvider"), o)
		})},
		{"updateIdentityProvider", "PUT", "/v1/admin/identity-providers/x", true, cr(func(r int64) (ChangeRequest, error) {
			return c.UpdateIdentityProvider(ctx, "x", definition(t, "IdentityProvider"), r, o)
		})},
		{"retireIdentityProvider", "DELETE", "/v1/admin/identity-providers/x", true, cr(func(r int64) (ChangeRequest, error) { return c.RetireIdentityProvider(ctx, "x", r, o) })},
		{"createSecretStore", "POST", "/v1/admin/secret-stores", false, cr(func(int64) (ChangeRequest, error) { return c.CreateSecretStore(ctx, definition(t, "SecretStore"), o) })},
		{"updateSecretStore", "PUT", "/v1/admin/secret-stores/x", true, cr(func(r int64) (ChangeRequest, error) {
			return c.UpdateSecretStore(ctx, "x", definition(t, "SecretStore"), r, o)
		})},
		{"retireSecretStore", "DELETE", "/v1/admin/secret-stores/x", true, cr(func(r int64) (ChangeRequest, error) { return c.RetireSecretStore(ctx, "x", r, o) })},
	}
}

// TestWritesUseTheDocumentsVerbAndPath: each write calls the verb and path of its operation.
func TestWritesUseTheDocumentsVerbAndPath(t *testing.T) {
	c, ws := newWriteServer(t)
	documented := map[string]operation{}
	for _, op := range operations(t) {
		documented[op.id] = op
	}
	for _, w := range writes(c, t) {
		if err := w.call(7); err != nil {
			t.Errorf("%s: %v", w.op, err)
			continue
		}
		r := ws.last()
		op := documented[w.op]
		want := strings.NewReplacer("{name}", "x", "{level}", "write").Replace(op.path)
		if r.Method != w.method || r.Method != op.method || r.URL.Path != want || want != w.path {
			t.Errorf("%s calls %s %s; the document says %s %s; the test expects %s %s", w.op, r.Method, r.URL.Path, op.method, want, w.method, w.path)
		}
	}
}

// TestUpdatesNeedTheirRevision is AC-6: an update, a state change or a
// deletion without the revision it is based on fails before any request.
func TestUpdatesNeedTheirRevision(t *testing.T) {
	c, ws := newWriteServer(t)
	for _, w := range writes(c, t) {
		if !w.revision {
			continue
		}
		for _, rev := range []int64{0, -1} {
			if err := w.call(rev); err == nil || !strings.Contains(err.Error(), "expectedRevision") {
				t.Errorf("%s with revision %d: %v", w.op, rev, err)
			}
		}
	}
	if n := ws.requests(); n != 0 {
		t.Errorf("%d requests were made without a revision", n)
	}
	ctx := context.Background()
	for name, err := range map[string]error{
		"an empty name":         func() error { _, err := c.UpdateSource(ctx, "", someSource(), 3, Options{}); return err }(),
		"an empty access level": func() error { _, err := c.RetireAccessLevel(ctx, "t", "", 3, Options{}); return err }(),
		"a platform definition for a secret store": func() error {
			_, err := c.CreateSecretStore(ctx, definition(t, "Platform"), Options{})
			return err
		}(),
		"an identity provider update with a store definition": func() error {
			_, err := c.UpdateIdentityProvider(ctx, "n", definition(t, "SecretStore"), 3, Options{})
			return err
		}(),
	} {
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if n := ws.requests(); n != 0 {
		t.Errorf("%d requests for refused calls", n)
	}
}

// TestStaleRevision is AC-6, second half: a stale revision is ErrConflict
// and is not retried (T-A6), whatever the status.
func TestStaleRevision(t *testing.T) {
	for _, tc := range []struct {
		code int
		slug string
		want error
	}{{409, "revision-conflict", ErrConflict}, {503, "unavailable", ErrUnavailable}, {429, "rate-limited", ErrUnavailable}} {
		ws := &writeServer{}
		ws.body = func(*http.Request) (int, string) {
			return tc.code, `{"type":"urn:ligo:problem:` + tc.slug + `","title":"x","status":` + http.StatusText(tc.code)[:0] + itoa(tc.code) + `,"detail":"stale"}`
		}
		c := newClient(t, ws)
		_, err := c.UpdateSource(context.Background(), "s", someSource(), 3, Options{})
		if !errors.Is(err, tc.want) {
			t.Errorf("%d: %v", tc.code, err)
		}
		if n := ws.requests(); n != 1 {
			t.Errorf("%d: a mutation was sent %d times", tc.code, n)
		}
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// TestFilingBody: the spec, the revision and the options are in one JSON
// object, and what the call returns is the change request.
func TestFilingBody(t *testing.T) {
	c, ws := newWriteServer(t)
	ctx := context.Background()
	o := Options{ApprovalReference: "CHG-42", AutomationContext: map[string]any{"run": "tf-1", "by": "terraform"}}
	cr, err := c.UpdateSource(ctx, "s", someSource(), 3, o)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Status != "PENDING" || cr.ResourceName != "s" || len(cr.AwaitingApproval) != 1 {
		t.Errorf("the change request: %+v", cr)
	}
	b := ws.lastBody(t)
	if b["expectedRevision"] != float64(3) || b["approvalReference"] != "CHG-42" || b["identity"] == nil || b["metadata"] == nil {
		t.Errorf("the body: %v", b)
	}
	if ctxMap, _ := b["automationContext"].(map[string]any); ctxMap["run"] != "tf-1" {
		t.Errorf("automationContext: %v", b["automationContext"])
	}
	if _, err := c.CreateSource(ctx, someSource(), Options{}); err != nil {
		t.Fatal(err)
	}
	if b := ws.lastBody(t); b["expectedRevision"] != nil || b["approvalReference"] != nil || b["automationContext"] != nil || b["managed"] != nil {
		t.Errorf("a creation carries no revision and no empty options: %v", b)
	}
	// a deletion: the revision is in the query, the options in the body
	if _, err := c.DeleteBinding(ctx, "b", 9, o); err != nil {
		t.Fatal(err)
	}
	if q := ws.last().URL.Query().Get("expectedRevision"); q != "9" {
		t.Errorf("DeleteBinding sent expectedRevision=%q", q)
	}
	if b := ws.lastBody(t); b["approvalReference"] != "CHG-42" || b["expectedRevision"] != nil {
		t.Errorf("DeleteBinding body: %v", b)
	}
	// a binding with an inline source and a wait
	spec := someBinding()
	spec.InlineSource = &SourceSpec{}
	*spec.InlineSource = someSource()
	if _, err := c.CreateBinding(ctx, spec, true, Options{}); err != nil {
		t.Fatal(err)
	}
	if ws.last().URL.Query().Get("wait") != "true" || ws.lastBody(t)["inlineSource"] == nil {
		t.Errorf("a binding with an inline source and a wait: %s %v", ws.last().URL.RawQuery, ws.lastBody(t))
	}
	if _, err := c.CreateBinding(ctx, someBinding(), false, Options{}); err != nil || ws.last().URL.Query().Has("wait") {
		t.Errorf("no wait: %s, %v", ws.last().URL.RawQuery, err)
	}
}

// TestInstanceFiling is AC-13 for the writes: a creation returns the change
// request, PENDING and awaiting its owner, and does not claim the store exists.
func TestInstanceFiling(t *testing.T) {
	c, ws := newWriteServer(t)
	cr, err := c.CreateSecretStore(context.Background(), definition(t, "SecretStore"), Options{})
	if err != nil || cr.Status != "PENDING" {
		t.Fatalf("%+v, %v", cr, err)
	}
	b := ws.lastBody(t)
	if b["kind"] != "SecretStore" || b["type"] != "x" || b["config"] == nil {
		t.Errorf("the definition went out as %v", b)
	}
}

// TestAccounts: an account is registered and retired at once.
func TestAccounts(t *testing.T) {
	c, ws := newWriteServer(t)
	ctx := context.Background()
	a, err := c.RegisterAccount(ctx, "ops", "Operations")
	if err != nil || a.Name != "ops" || a.Status != "ACTIVE" {
		t.Errorf("%+v, %v", a, err)
	}
	if b := ws.lastBody(t); b["name"] != "ops" || b["displayName"] != "Operations" {
		t.Errorf("body %v", b)
	}
	if a, err = c.RetireAccount(ctx, "ops"); err != nil || a.Status != "RETIRED" {
		t.Errorf("%+v, %v", a, err)
	}
	if _, err := c.RegisterAccount(ctx, "", ""); err == nil {
		t.Error("an empty name was accepted")
	}
	if _, err := c.RetireAccount(ctx, ""); err == nil {
		t.Error("an empty name was accepted")
	}
}

// TestManagedOption: Managed is sent as it is, true to set the lock, false to
// release it, and left out when nil.
func TestManagedOption(t *testing.T) {
	c, ws := newWriteServer(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		m    *bool
		want any
	}{"set": {ptr(true), true}, "release": {ptr(false), false}, "unchanged": {nil, nil}} {
		if _, err := c.CreateSource(ctx, someSource(), Options{Managed: tc.m}); err != nil {
			t.Fatal(err)
		}
		if got := ws.lastBody(t)["managed"]; got != tc.want {
			t.Errorf("%s: managed = %v, want %v", name, got, tc.want)
		}
	}
}

func ptr[T any](v T) *T { return &v }

// TestNoDecisionMethods is T-A4: the package has no method for the decisions
// of people.
func TestNoDecisionMethods(t *testing.T) {
	for _, op := range operations(t) {
		switch op.id {
		case "approveChangeRequest", "declineChangeRequest", "ratifyChangeRequest", "revertChangeRequest", "breakGlass",
			"liftHold", "releaseSource", "releaseTarget", "releaseBinding":
			if !contains(notYet, op.id) {
				t.Errorf("%s is in the package", op.id)
			}
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
