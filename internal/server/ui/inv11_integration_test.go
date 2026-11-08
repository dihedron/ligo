//go:build integration

package ui

import (
	"context"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"uuid"
)

// unaudited are the UI's non-GET routes that change no state of their own:
// a preference in the browser's cookie, read-only checks, or a workflow that
// audits itself.
var unaudited = map[string]string{
	"POST /ui/preferences/theme":           "a cookie in the browser",
	"POST /ui/sources/test":                "a read-only check",
	"POST /ui/targets/preview":             "a read-only check",
	"POST /ui/bindings/governance-preview": "a read-only check",
	"POST /ui/bindings/{name}/retry":       "audited by the workflow: TestAC09",
	"POST /ui/bindings/{name}/rotate":      "audited by the workflow: TestRotate",
}

var uiRoute = regexp.MustCompile(`mux\.HandleFunc\("((?:POST|PUT|PATCH|DELETE) [^"]+)"`)

// TestINV11Routes sends a real request to every state-changing route of the
// web UI and finds its audit entry through the request's ID. The routes are
// read from server.go, so a route added without a row here fails the test.
func TestINV11Routes(t *testing.T) {
	v := sessionSetup(t)
	ctx := context.Background()
	x := fixture(t, v)
	ledger := uuid.NewV7()
	source, target := "inv-src-"+x, "inv-tgt-"+x
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = v.owner.Exec(ctx, "delete from bindings where name like $1", "%"+x)
		_, _ = v.owner.Exec(ctx, "delete from change_requests where resource_name like $1", "%"+x)
		for _, table := range []string{"target_access_levels", "target_network_flows"} {
			_, _ = v.owner.Exec(ctx, "delete from "+table+" where target_id in (select id from targets where name = any($1))", []string{target, "ltgt-" + x})
		}
	})
	v.dir.groups[v.user] = []string{operators}
	b, a, g := v.browser(t), v.browser(t), v.browser(t)
	exercised := map[string]bool{}

	// act sends the request and wants the action audited under its request ID;
	// it answers the change request the response redirects to, if any.
	act := func(c *browser, pattern, action, path string, form url.Values) string {
		t.Helper()
		method, _, _ := strings.Cut(pattern, " ")
		resp, body := c.do(method, path, form)
		if resp.StatusCode >= 400 {
			t.Fatalf("%s: %d %s", pattern, resp.StatusCode, body)
		}
		var n int
		if err := v.owner.QueryRow(ctx, "select count(*) from audit_log where request_id = $1 and action = $2",
			resp.Header.Get("X-Request-Id"), action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("%s: no %s entry for its request", pattern, action)
		}
		exercised[pattern] = true
		id, _ := strings.CutPrefix(resp.Header.Get("HX-Redirect"), "/ui/change-requests/")
		return id
	}
	filed := func(id string) {
		t.Helper()
		v.approve(t, uuid.MustParse(id))
	}

	// signing in and out
	s := v.browser(t)
	_, page := s.do("GET", "/ui/login", nil)
	prelogin := preloginField.FindStringSubmatch(page)
	if prelogin == nil {
		t.Fatalf("no pre-login field: %s", page)
	}
	act(s, "POST /ui/login", "SESSION_LOGIN", "/ui/login", url.Values{"prelogin": {prelogin[1]}, "username": {v.user}, "password": {"right"}})
	s.page()
	act(s, "POST /ui/logout", "SESSION_LOGOUT", "/ui/logout", url.Values{})
	b.signIn("right")
	b.page()
	a.signInAs("a"+v.user, "right")
	a.page()
	if resp := g.signInAs("g"+v.user, "right"); resp.StatusCode >= 400 {
		t.Fatalf("the breaker's login: %d", resp.StatusCode)
	}
	_, form := g.do("GET", "/ui/break-glass/new-form", nil, "HX-Request", "")
	if m := csrfMeta.FindStringSubmatch(form); m != nil {
		g.csrf = m[1]
	}

	// accounts
	withAccounts(v)
	k := accountAdmin(t, v)
	account := accountName()
	act(k, "POST /ui/accounts", "SYSTEM_ACCOUNT_REGISTERED", "/ui/accounts", url.Values{"name": {account}})
	act(k, "POST /ui/accounts/{name}/retire", "SYSTEM_ACCOUNT_RETIRED", "/ui/accounts/"+account+"/retire", url.Values{})

	// sources
	src := url.Values{"name": {source}, "trustDomain": {"prod.internal"}, "svidRegex": {`^spiffe://prod\.internal/ns/inv/sa/` + x + `$`}, "visibility": {"PRIVATE"}}
	filed(act(b, "POST /ui/sources", "CR_CREATED", "/ui/sources", src))
	src.Set("description", "described")
	src.Set("expectedRevision", "1")
	filed(act(b, "PUT /ui/sources/{name}", "CR_CREATED", "/ui/sources/"+source, src))
	act(b, "POST /ui/sources/{name}/{op}", "CR_CREATED", "/ui/sources/"+source+"/deprecate", url.Values{"expectedRevision": {"2"}})

	// targets
	tgt := url.Values{"name": {target}, "platform": {"oracle-prod"}, "jurisdiction": {"dc/corp-prod/ledger"}, "def.schema": {"LEDGER"},
		"level.0.name": {"read"}, "level.0.grant.roles": {"LEDGER_RO_ROLE"}, "level.1.name": {"write"},
		"level.1.grant.roles": {"LEDGER_RO_ROLE", "LEDGER_RW_ROLE"}, "visibility": {"PUBLIC"}, "networkFlows": {"[]"}}
	filed(act(b, "POST /ui/targets", "CR_CREATED", "/ui/targets", tgt))
	tgt.Set("description", "described")
	tgt.Set("expectedRevision", "1")
	filed(act(b, "PUT /ui/targets/{name}", "CR_CREATED", "/ui/targets/"+target, tgt))
	filed(act(b, "POST /ui/targets/{name}/access-levels/{level}/{op}", "CR_CREATED", "/ui/targets/"+target+"/access-levels/write/deprecate", url.Values{"expectedRevision": {"2"}}))
	act(b, "POST /ui/targets/{name}/{op}", "CR_CREATED", "/ui/targets/"+target+"/deprecate", url.Values{"expectedRevision": {"3"}})

	// decisions
	decide := "POST /ui/change-requests/{id}/{action}"
	cr := v.file(t, v.user, 1, x)
	act(a, decide, "CR_SIDE_APPROVED", "/ui/change-requests/"+cr.ID.String()+"/approve", url.Values{"payloadSha256": {cr.PayloadSHA256}, "side": {cr.Sides[0].Name}})
	cr = v.file(t, v.user, 2, x)
	act(a, decide, "CR_SIDE_DECLINED", "/ui/change-requests/"+cr.ID.String()+"/decline", url.Values{"side": {cr.Sides[0].Name}, "comment": {"not now"}})
	cr = v.file(t, v.user, 3, x)
	act(b, decide, "CR_WITHDRAWN", "/ui/change-requests/"+cr.ID.String()+"/withdraw", url.Values{})

	// a binding: applied, then every way of changing it
	name := "src-" + x + "-tgt-" + x
	filed(act(b, "POST /ui/bindings", "CR_CREATED", "/ui/bindings", url.Values{"target": {"tgt-" + x}, "accessLevel": {"read"}, "source": {"src-" + x}, "name": {name}}))
	if _, err := v.owner.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	id := act(b, "PUT /ui/bindings/{name}", "CR_CREATED", "/ui/bindings/"+name, url.Values{"accessLevel": {"read"}, "purpose": {"audits"}, "expectedRevision": {"1"}})
	act(b, decide, "CR_WITHDRAWN", "/ui/change-requests/"+id+"/withdraw", url.Values{})
	act(b, "POST /ui/targets/{name}/bindings/revoke", "CR_CREATED", "/ui/targets/tgt-"+x+"/bindings/revoke", url.Values{"sourceJurisdiction": {"dc/*"}, "comment": {"incident"}})
	if err := v.owner.QueryRow(ctx, "select id::text from change_requests where resource_name = $1 and status = 'PENDING'", name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	act(b, decide, "CR_WITHDRAWN", "/ui/change-requests/"+id+"/withdraw", url.Values{})
	act(b, "DELETE /ui/bindings/{name}", "CR_CREATED", "/ui/bindings/"+name+"?expectedRevision=1", nil)

	// break-glass, in dc/corp-prod/ledger, where the role dc/corp-prod/* applies
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`insert into sources (id, name, jurisdiction, trust_domain, svid_regex, visibility, created_by, updated_by) values ($1, $2, 'dc/corp-prod/ledger',
			'prod.internal', $3, 'PUBLIC', 't', 't')`, []any{uuid.NewV7(), "lsrc-" + x, `^spiffe://prod\.internal/ns/ledger/sa/` + x + `$`}},
		{`insert into sources (id, name, jurisdiction, trust_domain, svid_regex, visibility, created_by, updated_by) values ($1, $2, 'dc/corp-prod/ledger',
			'prod.internal', $3, 'PUBLIC', 't', 't')`, []any{uuid.NewV7(), "lsrc2-" + x, `^spiffe://prod\.internal/ns/ledger2/sa/` + x + `$`}},
		{`insert into targets (id, name, platform, platform_type, realm, jurisdiction, platform_jurisdiction, definition, visibility, created_by, updated_by)
			values ($1, $2, 'oracle-prod', 'oracle.v1', 'prod', 'dc/corp-prod/ledger', 'dc/corp-prod', '{}', 'PUBLIC', 't', 't')`, []any{ledger, "ltgt-" + x}},
		{`insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{}', '[]')`, []any{ledger}},
	} {
		if _, err := v.owner.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	emergency := func(name, src string) url.Values {
		return url.Values{"operation": {"CREATE"}, "name": {name}, "source": {src}, "target": {"ltgt-" + x}, "accessLevel": {"read"},
			"justification": {"payments outage, the ledger read path is needed now"}, "incidentReference": {"INC0012345"}, "ttl": {"1h"}, "password": {"right"}}
	}
	act(g, "POST /ui/break-glass", "BREAK_GLASS_USED", "/ui/break-glass", emergency("bg1-"+x, "lsrc-"+x))
	act(g, "POST /ui/break-glass", "BREAK_GLASS_USED", "/ui/break-glass", emergency("bg2-"+x, "lsrc2-"+x))
	crOf := func(name string) string {
		t.Helper()
		var id string
		if err := v.owner.QueryRow(ctx, "select break_glass_cr_id::text from bindings where name = $1", name).Scan(&id); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return id
	}
	act(a, decide, "BREAK_GLASS_RATIFIED", "/ui/change-requests/"+crOf("bg1-"+x)+"/ratify", url.Values{"side": {"TARGET"}, "comment": {"confirmed"}})
	if _, err := v.owner.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", "bg2-"+x); err != nil {
		t.Fatal(err)
	}
	act(a, decide, "BREAK_GLASS_REVERT_STARTED", "/ui/change-requests/"+crOf("bg2-"+x)+"/revert", url.Values{"comment": {"the incident is over"}})

	source2, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, m := range uiRoute.FindAllStringSubmatch(string(source2), -1) {
		routes = append(routes, m[1])
	}
	if len(routes) < 20 {
		t.Fatalf("only %d routes read from server.go", len(routes))
	}
	for _, p := range routes {
		if _, ok := unaudited[p]; !ok && !exercised[p] {
			t.Errorf("%s: a state-changing route that this test does not exercise", p)
		}
	}
	for p := range unaudited {
		if !slices.Contains(routes, p) {
			t.Errorf("%s: listed as unaudited, but not routed", p)
		}
	}
}
