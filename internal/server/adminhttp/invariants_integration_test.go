//go:build integration

package adminhttp

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	"github.com/dihedron/ligo/internal/config"
)

// unaudited are the state-changing methods' routes that change no state of
// their own: read-only checks, or a workflow that audits itself.
var unaudited = map[string]string{
	"POST /v1/admin/charter/evaluate":       "a read-only evaluation",
	"POST /v1/admin/sources/test":           "a read-only check",
	"POST /v1/admin/bindings/{name}/retry":  "audited by the workflow: TestAC09",
	"POST /v1/admin/bindings/{name}/rotate": "audited by the workflow: TestRotate",
}

// TestINV11Routes sends a real request to every state-changing route of the
// admin API and finds its audit entry through the request's ID. A route added
// without a row here fails the test.
func TestINV11Routes(t *testing.T) {
	v := setup(t, config.AdminListener{AllowBasicAuth: true})
	ctx := context.Background()
	olga, dora, admin := v.client(t, opID), v.client(t, appID), v.client(t, adminID)
	x := v.suffix
	exercised := map[string]bool{}

	// act sends the request and wants the action audited under its request ID.
	act := func(pattern, action string, c *http.Client, path string, body any, basic ...string) response {
		t.Helper()
		method, _, _ := strings.Cut(pattern, " ")
		r := v.do(t, c, method, path, body, basic...)
		if r.code >= 300 {
			t.Fatalf("%s: %d %v", pattern, r.code, r.body)
		}
		var n int
		if err := v.owner.QueryRow(ctx, "select count(*) from audit_log where request_id = $1 and action = $2",
			r.header.Get("X-Request-Id"), action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("%s: no %s entry for its request", pattern, action)
		}
		exercised[pattern] = true
		return r
	}
	// applied approves every side still open, with one approver per side.
	applied := func(r response) {
		t.Helper()
		cr, _ := r.body["changeRequest"].(map[string]any)
		sides, _ := cr["awaitingApproval"].([]any)
		for i, side := range sides {
			if a := v.do(t, []*http.Client{dora, admin}[i], "POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve",
				map[string]any{"payloadSha256": cr["payloadSha256"], "side": side}); a.code != 200 {
				t.Fatalf("approve %v: %+v", side, a)
			}
		}
	}
	id := func(r response) string {
		t.Helper()
		cr, _ := r.body["changeRequest"].(map[string]any)
		if cr == nil {
			t.Fatalf("no change request: %+v", r)
		}
		return cr["id"].(string)
	}
	approve := "POST /v1/admin/change-requests/{id}/approve"
	withdraw := "POST /v1/admin/change-requests/{id}/withdraw"
	decline := "POST /v1/admin/change-requests/{id}/decline"
	base := "/v1/admin/change-requests/"

	// sources
	source := "inv-src-" + x
	regex := `^spiffe://prod\.internal/ns/inv/sa/` + x + `$`
	doc := func(revision int) map[string]any {
		d := map[string]any{"metadata": map[string]string{"name": source},
			"identity":   map[string]any{"trustDomain": "prod.internal", "svidRegex": regex},
			"visibility": map[string]string{"mode": "PRIVATE"}, "expectedRevision": revision}
		if revision == 0 {
			delete(d, "expectedRevision")
		}
		return d
	}
	applied(act("POST /v1/admin/sources", "CR_CREATED", olga, "/v1/admin/sources", doc(0)))
	d := doc(1)
	d["description"] = "described"
	applied(act("PUT /v1/admin/sources/{name}", "CR_CREATED", olga, "/v1/admin/sources/"+source, d))
	act("POST /v1/admin/sources/{name}/{op}", "CR_CREATED", olga, "/v1/admin/sources/"+source+"/deprecate", map[string]any{"expectedRevision": 2})

	// targets
	target := "inv-tgt-" + x
	body := func(revision int, description string) map[string]any {
		b := map[string]any{"metadata": map[string]string{"name": target, "platform": "oracle-prod", "jurisdiction": "dc/corp-prod/ledger"},
			"description": description, "definition": map[string]string{"schema": "LEDGER_APP"}, "networkFlows": []any{},
			"accessLevels": []map[string]any{
				{"name": "read", "grants": map[string][]string{"roles": {"LEDGER_RO_ROLE"}}},
				{"name": "write", "grants": map[string][]string{"roles": {"LEDGER_RW_ROLE"}}},
			}, "visibility": map[string]string{"mode": "PRIVATE"}}
		if revision > 0 {
			b["expectedRevision"] = revision
		}
		return b
	}
	applied(act("POST /v1/admin/targets", "CR_CREATED", olga, "/v1/admin/targets", body(0, "")))
	applied(act("PUT /v1/admin/targets/{name}", "CR_CREATED", olga, "/v1/admin/targets/"+target, body(1, "described")))
	applied(act("POST /v1/admin/targets/{name}/access-levels/{level}/{op}", "CR_CREATED", olga,
		"/v1/admin/targets/"+target+"/access-levels/write/deprecate", map[string]any{"expectedRevision": 2}))
	act("POST /v1/admin/targets/{name}/{op}", "CR_CREATED", olga, "/v1/admin/targets/"+target+"/deprecate", map[string]any{"expectedRevision": 3})

	// a binding: applied, then every way of changing it
	act(approve, "CR_SIDE_APPROVED", dora, base+v.request.ID.String()+"/approve", map[string]string{"payloadSha256": v.request.PayloadSHA256})
	if _, err := v.owner.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", v.name); err != nil {
		t.Fatal(err)
	}
	if _, err := v.owner.Exec(ctx, `insert into sources (id, name, jurisdiction, trust_domain, svid_regex, visibility, created_by, updated_by)
		values ($1, $2, 'dc/corp-prod', 'prod.internal', $3, 'PUBLIC', 't', 't')`, uuid.NewV7(), "src2-"+x, `^spiffe://prod\.internal/ns/inv2/sa/`+x+`$`); err != nil {
		t.Fatal(err)
	}
	act("POST /v1/admin/bindings", "CR_CREATED", olga, "/v1/admin/bindings",
		map[string]string{"name": "inv2-" + x, "source": "src2-" + x, "target": "tgt-" + x, "accessLevel": "read"})
	update := map[string]any{"name": v.name, "source": "src-" + x, "target": "tgt-" + x, "accessLevel": "read", "purpose": "reporting", "expectedRevision": 1}
	r := act("PUT /v1/admin/bindings/{name}", "CR_CREATED", olga, "/v1/admin/bindings/"+v.name, update)
	act(withdraw, "CR_WITHDRAWN", olga, base+id(r)+"/withdraw", nil)
	r = v.do(t, olga, "PUT", "/v1/admin/bindings/"+v.name, update)
	act(decline, "CR_SIDE_DECLINED", dora, base+id(r)+"/decline", map[string]string{"comment": "not now"})
	revoked := act("POST /v1/admin/targets/{name}/bindings/revoke", "CR_CREATED", olga, "/v1/admin/targets/tgt-"+x+"/bindings/revoke",
		map[string]string{"sourceJurisdiction": "dc/*", "comment": "compromised workload"})
	crs, _ := revoked.body["changeRequests"].([]any)
	if len(crs) != 1 {
		t.Fatalf("revoke: %+v", revoked)
	}
	act(withdraw, "CR_WITHDRAWN", olga, base+crs[0].(map[string]any)["id"].(string)+"/withdraw", nil)
	act("DELETE /v1/admin/bindings/{name}", "CR_CREATED", olga, "/v1/admin/bindings/"+v.name+"?expectedRevision=1", nil)

	// break-glass, in dc/corp-prod/ledger, whose breakers livia belongs to
	ledger := uuid.NewV7()
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
		{`insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{"roles":["LEDGER_RO_ROLE"]}', '["role:LEDGER_RO_ROLE"]')`, []any{ledger}},
	} {
		if _, err := v.owner.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	emergency := func(name, src string) map[string]any {
		return map[string]any{"operation": "CREATE", "binding": map[string]string{"name": name, "source": src, "target": "ltgt-" + x, "accessLevel": "read"}, "ttl": "1h",
			"justification": "payments outage, the ledger read path is needed now", "incidentReference": "INC0012345"}
	}
	bg1 := act("POST /v1/admin/break-glass", "BREAK_GLASS_USED", v.client(t, ""), "/v1/admin/break-glass", emergency("bg1-"+x, "lsrc-"+x), "livia", "pw")
	bg2 := act("POST /v1/admin/break-glass", "BREAK_GLASS_USED", v.client(t, ""), "/v1/admin/break-glass", emergency("bg2-"+x, "lsrc2-"+x), "livia", "pw")
	if r := v.do(t, dora, "POST", base+id(bg1)+"/ratify", map[string]string{"side": "TARGET", "comment": "confirmed"}); r.code != 403 {
		t.Errorf("ratified by an SVID: %d %v", r.code, r.body)
	}
	act("POST /v1/admin/change-requests/{id}/ratify", "BREAK_GLASS_RATIFIED", v.client(t, ""), base+id(bg1)+"/ratify",
		map[string]string{"side": "TARGET", "comment": "confirmed"}, "lena", "pw")
	if _, err := v.owner.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", "bg2-"+x); err != nil {
		t.Fatal(err)
	}
	act("POST /v1/admin/change-requests/{id}/revert", "BREAK_GLASS_REVERT_STARTED", dora, base+id(bg2)+"/revert", map[string]string{"comment": "the incident is over"})

	// operations
	fake := v.s.Workflows.(*fakeWorkflows)
	fake.pending = []dbos.WorkflowStatus{{ID: "w1", ExecutorID: "gone-" + x, ApplicationVersion: "v2", CreatedAt: time.Now()}}
	act("POST /v1/admin/executors/{id}/recover", "SYSTEM_EXECUTOR_RECOVERED", admin, "/v1/admin/executors/gone-"+x+"/recover", nil)
	act("PUT /v1/admin/maintenance", "SYSTEM_MAINTENANCE_ENABLED", admin, "/v1/admin/maintenance", map[string]any{"enabled": true, "reason": "INV-11"})
	act("PUT /v1/admin/maintenance", "SYSTEM_MAINTENANCE_DISABLED", admin, "/v1/admin/maintenance", map[string]any{"enabled": false})
	act("POST /v1/admin/audit/exports", "SYSTEM_AUDIT_EXPORTED", admin, "/v1/admin/audit/exports",
		map[string]any{"through": newCheckpoint(t, v, zeroSigner(t)), "sha256": strings.Repeat("e", 64)})

	account := "inv" + x
	t.Cleanup(func() { _, _ = v.owner.Exec(context.Background(), "delete from accounts where name = $1", account) })
	act("POST /v1/admin/accounts", "SYSTEM_ACCOUNT_REGISTERED", admin, "/v1/admin/accounts", map[string]any{"name": account})
	act("POST /v1/admin/accounts/{name}/retire", "SYSTEM_ACCOUNT_RETIRED", admin, "/v1/admin/accounts/"+account+"/retire", nil)

	var routes []string
	for _, p := range (&Server{}).routes().patterns {
		if method, _, _ := strings.Cut(p, " "); method != "GET" {
			routes = append(routes, p)
		}
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

// TestINV17: a source's one jurisdiction comes from its regex, whose fixed beginning
// must identify exactly one; a binding's three jurisdictions are those of its source,
// its target and the target's platform, here all different.
func TestINV17(t *testing.T) {
	v := setup(t, config.AdminListener{})
	ctx := context.Background()
	admin, ada, dora := v.client(t, adminID), v.client(t, admin2ID), v.client(t, appID)
	x := v.suffix
	source := func(name, regex string) map[string]any {
		return map[string]any{"metadata": map[string]string{"name": name},
			"identity":   map[string]any{"trustDomain": "cloud.internal", "svidRegex": regex},
			"visibility": map[string]string{"mode": "PUBLIC"}}
	}
	approve := func(r response) {
		t.Helper()
		cr, _ := r.body["changeRequest"].(map[string]any)
		if cr == nil {
			t.Fatalf("no change request: %+v", r)
		}
		sides, _ := cr["awaitingApproval"].([]any)
		for _, side := range sides {
			c := map[any]*http.Client{"TARGET": dora, "PARTY:security": v.client(t, secID)}[side]
			if c == nil {
				c = ada
			}
			if a := v.do(t, c, "POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve",
				map[string]any{"payloadSha256": cr["payloadSha256"], "side": side}); a.code != 200 {
				t.Fatalf("approve %v: %+v", side, a)
			}
		}
	}
	name := "fin-01-payments-inv17-" + x
	approve(v.do(t, admin, "POST", "/v1/admin/sources", source(name, `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/ns/`+x+`/sa/w$`)))
	var jurisdiction string
	if err := v.owner.QueryRow(ctx, "select jurisdiction from sources where name = $1", name).Scan(&jurisdiction); err != nil {
		t.Fatal(err)
	}
	if jurisdiction != "cloud/fin-01/payments" {
		t.Errorf("jurisdiction %q", jurisdiction)
	}
	if r := v.do(t, admin, "POST", "/v1/admin/sources", source("fin-01-inv17b-"+x, `^spiffe://cloud\.internal/acct/fin-01/tenant/[a-z]+/ns/`+x+`$`)); r.code != 422 || r.slug() != "urn:ligo:problem:jurisdiction-unresolvable" {
		t.Errorf("a regex across tenancies: %d %s", r.code, r.slug())
	}

	target := uuid.NewV7()
	if _, err := v.owner.Exec(ctx, `insert into targets (id, name, platform, platform_type, realm, jurisdiction, platform_jurisdiction, definition, visibility, created_by, updated_by)
		values ($1, $2, 'oracle-prod', 'oracle.v1', 'prod', 'dc/corp-prod/ledger', 'dc/corp-prod', '{}', 'PUBLIC', 't', 't')`, target, "ltgt-"+x); err != nil {
		t.Fatal(err)
	}
	if _, err := v.owner.Exec(ctx, `insert into target_access_levels (target_id, name, grants, privileges)
		values ($1, 'read', '{"roles":["LEDGER_RO_ROLE"]}', '["role:LEDGER_RO_ROLE"]')`, target); err != nil {
		t.Fatal(err)
	}
	binding := "fin-01-payments-inv17-b-" + x
	approve(v.do(t, admin, "POST", "/v1/admin/bindings", map[string]string{"name": binding, "source": name, "target": "ltgt-" + x, "accessLevel": "read"}))
	var sourceJurisdiction, targetJurisdiction, platformJurisdiction string
	if err := v.owner.QueryRow(ctx, "select source_jurisdiction, target_jurisdiction, platform_jurisdiction from bindings where name = $1", binding).
		Scan(&sourceJurisdiction, &targetJurisdiction, &platformJurisdiction); err != nil {
		t.Fatal(err)
	}
	if sourceJurisdiction != "cloud/fin-01/payments" || targetJurisdiction != "dc/corp-prod/ledger" || platformJurisdiction != "dc/corp-prod" {
		t.Errorf("the binding's jurisdictions: %s, %s, %s", sourceJurisdiction, targetJurisdiction, platformJurisdiction)
	}
}
