//go:build lab

package serve

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// The e2e of the lock (.specs/ligo-managed-resources.md, AC-M11): a pipeline
// owns a source, a target and a binding; people, other automation and the
// administrator are refused and nothing is filed; containment, the hold, the
// emergency paths and the release by an administrator work on the real
// service, through both replicas.

// problem is the slug of an RFC 9457 answer (urn:ligo:problem:SLUG).
func problem(body map[string]any) string {
	s, _ := body["type"].(string)
	return s[strings.LastIndex(s, ":")+1:]
}

// req is do, repeated while the per-principal rate limit answers 429: the
// request was refused before anything happened, so repeating it is safe.
func (a *admin) req(method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	for range 40 {
		code, b := a.do(method, path, body)
		if code != http.StatusTooManyRequests {
			return code, b
		}
		time.Sleep(500 * time.Millisecond)
	}
	return a.do(method, path, body)
}

// crCount is how many change requests exist for the resource.
func crCount(t *testing.T, a *admin, typ, name string) int {
	t.Helper()
	code, b := a.req("GET", "/v1/admin/change-requests?pageSize=200&resourceType="+typ+"&resourceName="+url.QueryEscape(name), nil)
	if code != http.StatusOK {
		t.Fatalf("list change requests: %d %v", code, b)
	}
	items, _ := b["items"].([]any)
	return len(items)
}

// managedBy is the owner a resource shows, "" when it has none.
func managedBy(t *testing.T, a *admin, kind, name string) string {
	t.Helper()
	code, b := a.req("GET", "/v1/admin/"+kind+"/"+name, nil)
	if code != http.StatusOK {
		t.Fatalf("get %s %s: %d %v", kind, name, code, b)
	}
	s, _ := b["metadata"].(map[string]any)["managedBy"].(string)
	return s
}

func revisionOf(t *testing.T, a *admin, kind, name string) int64 {
	t.Helper()
	code, b := a.req("GET", "/v1/admin/"+kind+"/"+name, nil)
	if code != http.StatusOK {
		t.Fatalf("get %s %s: %d %v", kind, name, code, b)
	}
	return int64(b["metadata"].(map[string]any)["revision"].(float64))
}

// openHolds are the open holds of a binding name.
func openHolds(t *testing.T, a *admin, name string) []map[string]any {
	t.Helper()
	code, b := a.req("GET", "/v1/admin/holds?binding="+url.QueryEscape(name), nil)
	if code != http.StatusOK {
		t.Fatalf("list holds: %d %v", code, b)
	}
	var out []map[string]any
	for _, h := range b["items"].([]any) {
		out = append(out, h.(map[string]any))
	}
	return out
}

// TestServeManaged is AC-M11 on the lab.
func TestServeManaged(t *testing.T) {
	pipeline, rival := newAdmin(t, "pipeline"), newAdmin(t, "rival")
	olga, ada, dora, sam := newAdmin(t, "olga"), newAdmin(t, "ada"), newAdmin(t, "dora"), newAdmin(t, "sam")
	bob, dave := newAdmin(t, "bob"), newAdmin(t, "dave") // people by LDAP: full access, and an approver
	livia := newAdmin(t, "livia")
	other := e2eEnv(t, "LIGO_E2E_ADMIN2")
	olga2, dave2 := newAdmin(t, "olga"), newAdmin(t, "dave")
	olga2.base, dave2.base = other, other
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	const pipelineID = "spiffe://prod.lab/ci/terraform"
	source, target, binding := "mg-src-"+x, "mg-ledger-"+x, "mg-"+x

	srcDoc := func(name string, extra map[string]any) map[string]any {
		d := map[string]any{"kind": "Source", "metadata": map[string]string{"name": name},
			"identity": map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/e2e/sa/w` + x + `$`,
				"sampleSpiffeIds": []string{"spiffe://prod.lab/ns/e2e/sa/w" + x}}, "visibility": map[string]string{"mode": "PRIVATE"}}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}
	tgtDoc := func(extra map[string]any) map[string]any {
		d := map[string]any{"kind": "Target", "metadata": map[string]string{"name": target, "platform": "pg-ledger", "jurisdiction": "dc/corp-prod/ledger"},
			"definition":   map[string]string{"database": "ledger", "schema": "ledger"},
			"accessLevels": []any{map[string]any{"name": "read", "grants": map[string][]string{"roles": {"LEDGER_RO_ROLE"}}}},
			"networkFlows": []any{map[string]any{"name": "ledger", "purpose": "DATA", "protocol": "TCP", "destination": "pg.ligo.lab",
				"ports": []int{5432}, "tls": true, "serverName": "pg.ligo.lab"}},
			"visibility": map[string]string{"mode": "PRIVATE"}}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}
	bindDoc := func(extra map[string]any) map[string]any {
		d := map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}
	owned := map[string]any{"managed": true, "approvalReference": "CHG-1"}

	// 1. the pipeline owns all three, applied at once by delegation
	for _, c := range []struct {
		typ, path string
		doc       map[string]any
	}{{"SOURCE", "sources", srcDoc(source, owned)}, {"TARGET", "targets", tgtDoc(owned)}, {"BINDING", "bindings", bindDoc(owned)}} {
		code, filed := pipeline.req("POST", "/v1/admin/"+c.path, c.doc)
		if code/100 != 2 {
			t.Fatalf("pipeline %s: %d %v", c.path, code, filed)
		}
		if cr, _ := filed["changeRequest"].(map[string]any); cr["status"] != "APPLIED" {
			t.Fatalf("pipeline %s: %v, want APPLIED by delegation", c.path, cr["status"])
		}
	}
	phase(t, olga, binding, "ACTIVE")
	for _, k := range [][2]string{{"sources", source}, {"targets", target}, {"bindings", binding}} {
		if got := managedBy(t, olga, k[0], k[1]); got != pipelineID {
			t.Errorf("%s %s: managedBy %q, want %q", k[0], k[1], got, pipelineID)
		}
	}
	t.Log("the pipeline owns a source, a target and a binding; the binding is ACTIVE")

	// 2 and 3. everybody else is refused, on both replicas, and nothing is filed
	before := map[string]int{"SOURCE": crCount(t, olga, "SOURCE", source), "TARGET": crCount(t, olga, "TARGET", target), "BINDING": crCount(t, olga, "BINDING", binding)}
	for _, who := range []struct {
		name string
		a    *admin
	}{{"olga", olga}, {"olga on the other replica", olga2}, {"ada, full access", ada}, {"bob, a person with full access", bob}, {"rival, trusted automation", rival}} {
		rs, rt, rb := revisionOf(t, who.a, "sources", source), revisionOf(t, who.a, "targets", target), revisionOf(t, who.a, "bindings", binding)
		for _, op := range []struct {
			what, method, path string
			body               any
		}{
			{"update source", "PUT", "/v1/admin/sources/" + source, srcDoc(source, map[string]any{"description": "x", "expectedRevision": rs, "approvalReference": "CHG-2"})},
			{"deprecate source", "POST", "/v1/admin/sources/" + source + "/deprecate", map[string]any{"expectedRevision": rs}},
			{"retire source", "POST", "/v1/admin/sources/" + source + "/retire", map[string]any{"expectedRevision": rs}},
			{"update target", "PUT", "/v1/admin/targets/" + target, tgtDoc(map[string]any{"description": "x", "expectedRevision": rt, "approvalReference": "CHG-2"})},
			{"deprecate target", "POST", "/v1/admin/targets/" + target + "/deprecate", map[string]any{"expectedRevision": rt}},
			{"retire target", "POST", "/v1/admin/targets/" + target + "/retire", map[string]any{"expectedRevision": rt}},
			{"update binding", "PUT", "/v1/admin/bindings/" + binding, bindDoc(map[string]any{"purpose": "x", "expectedRevision": rb, "approvalReference": "CHG-2"})},
		} {
			code, b := who.a.req(op.method, op.path, op.body)
			// a retirement of what bindings use is refused as in use first: the spare below proves the lock's answer
			if inUse := strings.HasPrefix(op.what, "retire") && problem(b) == "resource-in-use"; code != http.StatusConflict || (problem(b) != "resource-managed" && !inUse) {
				t.Errorf("%s: %s: %d %v, want 409 resource-managed", who.name, op.what, code, b)
			}
		}
	}
	if code, b := olga.req("PUT", "/v1/admin/sources/"+source, srcDoc(source, map[string]any{"managed": true, "expectedRevision": revisionOf(t, olga, "sources", source)})); code != http.StatusConflict && code != http.StatusForbidden {
		t.Errorf("a person's managed:true on a managed source: %d %v", code, b)
	}
	if code, b := olga.req("POST", "/v1/admin/sources", srcDoc("p-"+source, map[string]any{"managed": true})); code != http.StatusForbidden {
		t.Errorf("a person creates a managed source: %d %v, want 403", code, b)
	}
	if code, b := rival.req("PUT", "/v1/admin/sources/"+source, srcDoc(source, map[string]any{"managed": true, "expectedRevision": revisionOf(t, rival, "sources", source), "approvalReference": "CHG-3"})); code != http.StatusConflict {
		t.Errorf("a rival adopts what the pipeline owns: %d %v, want 409", code, b)
	}
	if code, b := pipeline.req("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": "out-" + source},
		"identity": map[string]any{"trustDomain": "test.lab", "svidRegex": `^spiffe://test\.lab/acct/fin-01/tenant/payments/ns/x/sa/` + x + `$`},
		"managed":  true, "approvalReference": "CHG-4", "visibility": map[string]string{"mode": "PRIVATE"}}); code != http.StatusForbidden {
		t.Errorf("the pipeline outside its jurisdictions: %d %v, want 403", code, b)
	}
	for typ, n := range before {
		name := map[string]string{"SOURCE": source, "TARGET": target, "BINDING": binding}[typ]
		if got := crCount(t, olga, typ, name); got != n {
			t.Errorf("%s %s: %d change requests, want %d: a refused change was filed", typ, name, got, n)
		}
	}
	t.Log("every other principal is refused on both replicas, and nothing is filed")

	// a managed source that nothing uses: its retirement is refused as managed
	spare := "mg-spare-" + x
	spareDoc := srcDoc(spare, owned)
	spareDoc["identity"] = map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/spare/sa/w` + x + `$`}
	if code, b := pipeline.req("POST", "/v1/admin/sources", spareDoc); code/100 != 2 {
		t.Fatalf("the spare source: %d %v", code, b)
	}
	for _, who := range []*admin{olga, ada, rival} {
		if code, b := who.req("POST", "/v1/admin/sources/"+spare+"/retire", map[string]any{"expectedRevision": revisionOf(t, who, "sources", spare)}); code != http.StatusConflict || problem(b) != "resource-managed" {
			t.Errorf("retire of an unused managed source: %d %v, want 409 resource-managed", code, b)
		}
	}

	// 4. the owner changes its own binding and keeps the lock
	rb := revisionOf(t, pipeline, "bindings", binding)
	if code, b := pipeline.req("PUT", "/v1/admin/bindings/"+binding, bindDoc(map[string]any{"purpose": "reporting", "expectedRevision": rb, "approvalReference": "CHG-5"})); code/100 != 2 {
		t.Fatalf("the owner updates its binding: %d %v", code, b)
	}
	phase(t, olga, binding, "ACTIVE")
	if got := managedBy(t, olga, "bindings", binding); got != pipelineID {
		t.Errorf("an update that does not say managed lost the lock: %q", got)
	}

	// 5. containment: the target's operator revokes, dora approves one side
	rb = revisionOf(t, olga, "bindings", binding)
	code, filed := olga.req("DELETE", fmt.Sprintf("/v1/admin/bindings/%s?expectedRevision=%d", binding, rb), nil)
	if code != http.StatusAccepted {
		t.Fatalf("containment: %d %v", code, filed)
	}
	if cr, _ := filed["changeRequest"].(map[string]any); cr["consent"] != "ANY" {
		t.Errorf("a revocation asks consent %v, want ANY", cr["consent"])
	}
	approveAll(t, dora, filed)
	phase(t, olga, binding, "")
	revoked(t)
	holds := openHolds(t, olga, binding)
	if len(holds) != 1 || holds[0]["basis"] != "CONTAINMENT" || holds[0]["managedBy"] != pipelineID {
		t.Fatalf("holds after the containment: %v", holds)
	}
	t.Log("containment revoked the managed binding and left a hold")

	// 6. the hold stops everyone, until a person lifts it
	for _, who := range []struct {
		name string
		a    *admin
		doc  map[string]any
	}{{"the pipeline", pipeline, bindDoc(owned)}, {"olga", olga, bindDoc(nil)}, {"olga on the other replica", olga2, bindDoc(nil)}} {
		if code, b := who.a.req("POST", "/v1/admin/bindings", who.doc); code != http.StatusConflict || problem(b) != "resource-held" {
			t.Errorf("%s re-creates a held binding: %d %v, want 409 resource-held", who.name, code, b)
		}
	}
	id := holds[0]["id"].(string)
	if code, b := pipeline.req("POST", "/v1/admin/holds/"+id+"/lift", map[string]any{"comment": "the pipeline lifts"}); code != http.StatusForbidden {
		t.Errorf("the pipeline lifts its own hold: %d %v, want 403", code, b)
	}
	if code, b := olga.req("POST", "/v1/admin/holds/"+id+"/lift", map[string]any{"comment": "an operator lifts"}); code != http.StatusForbidden {
		t.Errorf("an operator lifts: %d %v, want 403", code, b)
	}
	if code, b := dave2.req("POST", "/v1/admin/holds/"+id+"/lift", map[string]any{"comment": " "}); code != http.StatusUnprocessableEntity {
		t.Errorf("a lift without a comment: %d %v, want 422", code, b)
	}
	if code, b := dave2.req("POST", "/v1/admin/holds/"+id+"/lift", map[string]any{"comment": "contained and reviewed"}); code != http.StatusNoContent {
		t.Fatalf("dora lifts: %d %v", code, b)
	}
	if left := openHolds(t, olga, binding); len(left) != 0 {
		t.Errorf("holds after the lift: %v", left)
	}
	code, filed = pipeline.req("POST", "/v1/admin/bindings", bindDoc(owned))
	if code/100 != 2 {
		t.Fatalf("the pipeline re-creates after the lift: %d %v", code, filed)
	}
	phase(t, olga, binding, "ACTIVE")
	t.Log("the hold refused everyone, a person lifted it, the pipeline created the binding again")

	// 7. emergency: break-glass may change a managed binding, never ratifiably
	rb = revisionOf(t, olga, "bindings", binding)
	code, filed = livia.req("POST", "/v1/admin/break-glass", map[string]any{"operation": "UPDATE", "ttl": "1h",
		"binding":       bindDoc(map[string]any{"purpose": "emergency", "expectedRevision": rb}),
		"justification": "the ledger read path needs a change now", "incidentReference": "INC0012345"})
	if code/100 != 2 {
		t.Fatalf("break-glass update of a managed binding: %d %v", code, filed)
	}
	bg := filed["changeRequest"].(map[string]any)["id"].(string)
	if got := managedBy(t, olga, "bindings", binding); got != pipelineID {
		t.Errorf("a break-glass change moved the lock to %q", got)
	}
	if code, b := dave.req("POST", "/v1/admin/change-requests/"+bg+"/ratify", map[string]any{"side": "TARGET", "comment": "keep it"}); code != http.StatusConflict || problem(b) != "resource-managed" {
		t.Errorf("ratify of a break-glass change on a managed binding: %d %v, want 409 resource-managed", code, b)
	}
	// the incident is over: a person reverts it, which also keeps the policy's max_open free for the next run
	phase(t, olga, binding, "ACTIVE")
	if code, b := dave.req("POST", "/v1/admin/change-requests/"+bg+"/revert", map[string]any{"comment": "the incident is over"}); code/100 != 2 {
		t.Errorf("revert of the break-glass change: %d %v", code, b)
	}
	t.Log("break-glass changed the managed binding; its ratification is refused and a person reverted it (at its TTL it would revert by itself)")

	// 8. release by an administrator: four eyes, people only
	rs := revisionOf(t, bob, "sources", source)
	justification := "the pipeline that owned it was retired in March"
	for _, c := range []struct {
		what string
		a    *admin
		body map[string]any
		want int
	}{
		{"an operator", olga,
			map[string]any{"expectedRevision": rs, "justification": justification}, http.StatusForbidden},
		{"ada, full access by SVID", ada, map[string]any{"expectedRevision": rs, "justification": justification}, http.StatusForbidden},
		{"the owner's SVID", pipeline, map[string]any{"expectedRevision": rs, "justification": justification}, http.StatusForbidden},
		{"a short justification", bob, map[string]any{"expectedRevision": rs, "justification": "retired"}, http.StatusUnprocessableEntity},
	} {
		if code, b := c.a.req("POST", "/v1/admin/sources/"+source+"/release", c.body); code != c.want {
			t.Errorf("release by %s: %d %v, want %d", c.what, code, b, c.want)
		}
	}
	code, filed = bob.req("POST", "/v1/admin/sources/"+source+"/release", map[string]any{"expectedRevision": rs, "justification": justification})
	if code != http.StatusAccepted {
		t.Fatalf("release by an administrator: %d %v", code, filed)
	}
	cr := filed["changeRequest"].(map[string]any)
	if cr["consent"] != "ALL" || cr["status"] != "PENDING" {
		t.Fatalf("the release: %v, want PENDING with consent ALL", cr)
	}
	if got := managedBy(t, olga, "sources", source); got != pipelineID {
		t.Fatalf("released before it was approved: %q", got)
	}
	if code, b := bob.req("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve", map[string]any{"payloadSha256": cr["payloadSha256"], "side": cr["awaitingApproval"].([]any)[0]}); code != http.StatusForbidden {
		t.Errorf("the requester approves its own release: %d %v, want 403", code, b)
	}
	for i, who := range []*admin{dora, sam, dave} { // two distinct people, one side each
		side := cr["awaitingApproval"].([]any)[0]
		code, b := who.req("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve", map[string]any{"payloadSha256": cr["payloadSha256"], "side": side, "comment": "e2e"})
		if code != http.StatusOK {
			t.Fatalf("approver %d: %d %v", i, code, b)
		}
		cr = b["changeRequest"].(map[string]any)
		if cr["status"] != "PENDING" {
			break
		}
	}
	if cr["status"] != "APPLIED" {
		t.Fatalf("the release ended %v", cr["status"])
	}
	if got := managedBy(t, olga, "sources", source); got != "" {
		t.Errorf("released, managedBy %q", got)
	}
	if code, b := olga.req("PUT", "/v1/admin/sources/"+source, srcDoc(source, map[string]any{"description": "edited by a person", "expectedRevision": revisionOf(t, olga, "sources", source)})); code/100 != 2 {
		t.Errorf("a person edits the released source: %d %v", code, b)
	}
	t.Log("the administrator's release needed two people and freed the source")

	// 9. a race: two automations file the same new managed source name
	for i := range 10 {
		name := fmt.Sprintf("mg-race-%d-%s", i, x)
		doc := srcDoc(name, owned)
		doc["identity"] = map[string]any{"trustDomain": "prod.lab", "svidRegex": fmt.Sprintf(`^spiffe://prod\.lab/ns/race/sa/%d%s$`, i, x)}
		var wg sync.WaitGroup
		codes := make([]int, 2)
		for j, a := range []*admin{pipeline, rival} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[j], _ = a.req("POST", "/v1/admin/sources", doc)
			}()
		}
		wg.Wait()
		if wins := btoi(codes[0]/100 == 2) + btoi(codes[1]/100 == 2); wins != 1 {
			t.Errorf("race %d: answers %v, want exactly one creation", i, codes)
		}
		if got := managedBy(t, olga, "sources", name); got != pipelineID && got != "spiffe://prod.lab/ci/other" {
			t.Errorf("race %d: owner %q", i, got)
		}
	}

	// the audit entries and the metric are checked by lab.sh serve test-managed, in the database
	if code, v := bob.req("GET", "/v1/admin/audit/verify", nil); code != http.StatusOK || v["valid"] != true {
		t.Errorf("audit verify: %d %v", code, v)
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
