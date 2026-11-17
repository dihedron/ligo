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

// The pre-release campaign's gaps (terraform-provider-ligo
// .specs/ligo-prerelease-campaign.md, phase 1): what no lab suite covered.
// Lifecycle: the release of a binding and of a target by people, the
// containment of all the bindings of a source on a target, the expiry of a
// binding on a live server. Break-glass: the policy's limits and the revert at
// the time-to-live. Rate limiting: 429 with Retry-After, per principal.

const campaignPipeline = "spiffe://prod.lab/ci/terraform"

// campaignWorld is a managed source, target and binding, made by the pipeline.
type campaignWorld struct {
	x, source, target, binding string
	pipeline                   *admin
}

func (w campaignWorld) srcDoc(extra map[string]any) map[string]any {
	d := map[string]any{"kind": "Source", "metadata": map[string]string{"name": w.source},
		"identity": map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/cmp/sa/` + w.source + `$`,
			"sampleSpiffeIds": []string{"spiffe://prod.lab/ns/cmp/sa/" + w.source}}, "visibility": map[string]string{"mode": "PRIVATE"}}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func (w campaignWorld) tgtDoc(extra map[string]any) map[string]any {
	d := map[string]any{"kind": "Target", "metadata": map[string]string{"name": w.target, "platform": "pg-ledger", "jurisdiction": "dc/corp-prod/ledger"},
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

func (w campaignWorld) bindDoc(extra map[string]any) map[string]any {
	d := map[string]any{"name": w.binding, "source": w.source, "target": w.target, "accessLevel": "read"}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

// newCampaignWorld files the three by delegation and waits for the binding.
func newCampaignWorld(t *testing.T, pipeline, watcher *admin, name string, binding map[string]any) campaignWorld {
	t.Helper()
	w := campaignWorld{x: e2eEnv(t, "LIGO_E2E_SUFFIX"), pipeline: pipeline}
	w.source, w.target, w.binding = "cmp-src-"+name+"-"+w.x, "cmp-tgt-"+name+"-"+w.x, "cmp-"+name+"-"+w.x
	owned := map[string]any{"managed": true, "approvalReference": "CHG-C1"}
	for _, c := range []struct {
		path string
		doc  map[string]any
	}{{"sources", w.srcDoc(owned)}, {"targets", w.tgtDoc(owned)}, {"bindings", w.bindDoc(merge(owned, binding))}} {
		if code, b := pipeline.req("POST", "/v1/admin/"+c.path, c.doc); code/100 != 2 {
			t.Fatalf("pipeline %s: %d %v", c.path, code, b)
		}
	}
	phase(t, watcher, w.binding, "ACTIVE")
	return w
}

func merge(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// decideRelease files the release of kind/name by bob and has two other people
// approve it: four eyes, people only.
func decideRelease(t *testing.T, bob *admin, approvers []*admin, kind, name, why string) {
	t.Helper()
	rev := revisionOf(t, bob, kind, name)
	code, filed := bob.req("POST", "/v1/admin/"+kind+"/"+name+"/release", map[string]any{"expectedRevision": rev, "justification": why})
	if code != http.StatusAccepted {
		t.Fatalf("release of %s %s: %d %v", kind, name, code, filed)
	}
	cr := filed["changeRequest"].(map[string]any)
	if cr["consent"] != "ALL" {
		t.Fatalf("the release of %s %s: consent %v, want ALL", kind, name, cr["consent"])
	}
	for i := 0; cr["status"] == "PENDING"; i++ {
		if i >= len(approvers) {
			t.Fatalf("release of %s %s still pending after %d approvers: %v", kind, name, i, cr)
		}
		code, b := approvers[i].req("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve",
			map[string]any{"payloadSha256": cr["payloadSha256"], "side": cr["awaitingApproval"].([]any)[0], "comment": "campaign"})
		if code != http.StatusOK {
			t.Fatalf("approval %d of the release of %s %s: %d %v", i, kind, name, code, b)
		}
		cr = b["changeRequest"].(map[string]any)
	}
	if cr["status"] != "APPLIED" {
		t.Fatalf("release of %s %s ended %v", kind, name, cr["status"])
	}
}

// TestServeCampaignLifecycle: releases of a binding and a target, the
// containment of a source's bindings on a target, the expiry of a binding.
func TestServeCampaignLifecycle(t *testing.T) {
	pipeline, olga := newAdmin(t, "pipeline"), newAdmin(t, "olga")
	dora, sam, bob := newAdmin(t, "dora"), newAdmin(t, "sam"), newAdmin(t, "bob")
	w := newCampaignWorld(t, pipeline, olga, "lc", nil)
	why := "the pipeline that owned it was retired, campaign"

	// the release of a managed binding: an operator and an SVID cannot, people can
	rb := revisionOf(t, olga, "bindings", w.binding)
	if code, b := olga.req("POST", "/v1/admin/bindings/"+w.binding+"/release", map[string]any{"expectedRevision": rb, "justification": why}); code != http.StatusForbidden {
		t.Errorf("an operator releases a binding: %d %v, want 403", code, b)
	}
	if code, b := pipeline.req("POST", "/v1/admin/bindings/"+w.binding+"/release", map[string]any{"expectedRevision": rb, "justification": why}); code != http.StatusForbidden {
		t.Errorf("the owner releases a binding: %d %v, want 403", code, b)
	}
	decideRelease(t, bob, []*admin{dora, sam}, "bindings", w.binding, why)
	phase(t, olga, w.binding, "ACTIVE") // the release is an update: the binding provisions again, and is busy meanwhile
	if got := managedBy(t, olga, "bindings", w.binding); got != "" {
		t.Errorf("the binding is released and managedBy is %q", got)
	}
	if code, b := olga.req("PUT", "/v1/admin/bindings/"+w.binding, w.bindDoc(map[string]any{"purpose": "edited by a person", "expectedRevision": revisionOf(t, olga, "bindings", w.binding)})); code/100 != 2 {
		t.Errorf("a person edits the released binding: %d %v", code, b)
	} else if cr, _ := b["changeRequest"].(map[string]any); cr["status"] == "PENDING" {
		approveAll(t, dora, b)
	}
	phase(t, olga, w.binding, "ACTIVE")
	t.Log("the release of a binding needed two people; the owner and an operator were refused")

	// the release of a managed target
	if code, b := pipeline.req("POST", "/v1/admin/targets/"+w.target+"/release", map[string]any{"expectedRevision": revisionOf(t, olga, "targets", w.target), "justification": why}); code != http.StatusForbidden {
		t.Errorf("the owner releases a target: %d %v, want 403", code, b)
	}
	decideRelease(t, bob, []*admin{dora, sam}, "targets", w.target, why)
	if got := managedBy(t, olga, "targets", w.target); got != "" {
		t.Errorf("the target is released and managedBy is %q", got)
	}
	t.Log("the release of a target needed two people")

	// containment: all the bindings of a source on a target
	if code, b := olga.req("POST", "/v1/admin/targets/"+w.target+"/bindings/revoke", map[string]any{"comment": "no scope"}); code/100 == 2 {
		t.Errorf("revoke-bindings without a source or jurisdiction: %d %v, want a refusal", code, b)
	}
	code, b := olga.req("POST", "/v1/admin/targets/"+w.target+"/bindings/revoke", map[string]any{"source": w.source, "comment": "containment, campaign", "approvalReference": "INC-C1"})
	if code/100 != 2 {
		t.Fatalf("revoke-bindings: %d %v", code, b)
	}
	crs, _ := b["changeRequests"].([]any)
	if len(crs) != 1 {
		t.Fatalf("revoke-bindings of one binding filed %d requests: %v", len(crs), b)
	}
	approveAll(t, dora, map[string]any{"changeRequest": crs[0]})
	phase(t, olga, w.binding, "")
	if left := openHolds(t, olga, w.binding); len(left) != 0 {
		t.Errorf("an unmanaged binding's containment left holds: %v", left)
	}
	t.Log("revoke-bindings revoked the source's binding on the target")
}

// TestServeCampaignExpiryCreate files a managed binding that expires in 65
// minutes (the least ligo accepts is an hour); lab.sh then moves its expiry
// into the past in the database, as the integration tests do, and
// TestServeCampaignExpiryCheck waits for ligo's expirer to revoke it.
func TestServeCampaignExpiryCreate(t *testing.T) {
	pipeline, olga := newAdmin(t, "pipeline"), newAdmin(t, "olga")
	exp := time.Now().Add(65 * time.Minute).UTC().Format(time.RFC3339)
	w := newCampaignWorld(t, pipeline, olga, "exp", map[string]any{"expiresAt": exp})
	if got := managedBy(t, olga, "bindings", w.binding); got != campaignPipeline {
		t.Errorf("managedBy %q", got)
	}
	t.Logf("binding %s expires at %s", w.binding, exp)
}

func TestServeCampaignExpiryCheck(t *testing.T) {
	olga := newAdmin(t, "olga")
	name := "cmp-exp-" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	deadline := time.Now().Add(8 * time.Minute)
	for {
		code, b := olga.req("GET", "/v1/admin/bindings/"+name, nil)
		st, _ := b["status"].(map[string]any)
		if code == http.StatusNotFound || (code == http.StatusOK && st["phase"] != "ACTIVE") {
			t.Logf("binding %s expired: %d, phase %v", name, code, st["phase"])
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("binding %s, expired in the database, is still %v after 8 minutes", name, st["phase"])
		}
		time.Sleep(5 * time.Second)
	}
	phase(t, olga, name, "")
	revoked(t)
}

// TestServeCampaignBreakGlassLimits: the policy of dc/corp-prod/* (max_ttl 4h,
// max_open 3) and the revert at the time-to-live.
func TestServeCampaignBreakGlassLimits(t *testing.T) {
	pipeline, olga, dave, livia := newAdmin(t, "pipeline"), newAdmin(t, "olga"), newAdmin(t, "dave"), newAdmin(t, "livia")
	// what an earlier, failed run left open would use up the policy's max_open
	revertOpen := func() {
		code, b := olga.req("GET", "/v1/admin/break-glass?pageSize=200", nil)
		if code != http.StatusOK {
			return
		}
		for _, it := range b["items"].([]any) {
			if cr, _ := it.(map[string]any); strings.HasPrefix(fmt.Sprint(cr["resourceName"]), "cmp-bg") && cr["status"] == "APPLIED" {
				_, _ = dave.req("POST", "/v1/admin/change-requests/"+fmt.Sprint(cr["id"])+"/revert", map[string]any{"comment": "campaign cleanup"})
			}
		}
	}
	revertOpen()
	t.Cleanup(revertOpen)
	var worlds []campaignWorld
	for i := range 4 {
		worlds = append(worlds, newCampaignWorld(t, pipeline, olga, fmt.Sprintf("bg%d", i), map[string]any{"purpose": "original"}))
	}
	file := func(w campaignWorld, ttl string) (int, map[string]any) {
		return livia.req("POST", "/v1/admin/break-glass", map[string]any{"operation": "UPDATE", "ttl": ttl,
			"binding":       w.bindDoc(map[string]any{"purpose": "emergency", "expectedRevision": revisionOf(t, olga, "bindings", w.binding)}),
			"justification": "campaign: the limits of the policy", "incidentReference": "INC0099999"})
	}

	// max_ttl is 4h
	if code, b := file(worlds[0], "5h"); code/100 == 2 {
		t.Errorf("a break-glass of 5h under a 4h limit: %d %v, want a refusal", code, b)
	} else {
		t.Logf("5h refused: %d %s", code, problem(b))
	}

	// the time-to-live reverts a change by itself
	code, b := file(worlds[0], "5m")
	if code/100 != 2 {
		t.Fatalf("a break-glass of 5m: %d %v", code, b)
	}
	first := b["changeRequest"].(map[string]any)["id"].(string)

	// max_open is 3: the fourth open one is refused
	opened := []string{first}
	for i := 1; i <= 3; i++ {
		code, b := file(worlds[i], "1h")
		if i < 3 && code/100 != 2 {
			t.Fatalf("break-glass %d of 3 open: %d %v", i+1, code, b)
		}
		if i == 3 {
			if code/100 == 2 {
				t.Errorf("the fourth open break-glass was accepted: %d %v, want a refusal (max_open 3)", code, b)
				opened = append(opened, b["changeRequest"].(map[string]any)["id"].(string))
			} else {
				t.Logf("fourth open break-glass refused: %d %s", code, problem(b))
			}
			continue
		}
		opened = append(opened, b["changeRequest"].(map[string]any)["id"].(string))
	}

	// the first reverts at its TTL: ligo files a SYSTEM_REVERT request itself
	deadline := time.Now().Add(9 * time.Minute)
	for bindingPurpose(t, olga, worlds[0].binding) != "original" {
		if time.Now().After(deadline) {
			t.Fatalf("break-glass %s of 5m: the binding's purpose is still %q after 9 minutes", first, bindingPurpose(t, olga, worlds[0].binding))
		}
		time.Sleep(10 * time.Second)
	}
	phase(t, olga, worlds[0].binding, "ACTIVE")
	code, b = olga.req("GET", "/v1/admin/change-requests?pageSize=50&resourceType=BINDING&resourceName="+url.QueryEscape(worlds[0].binding), nil)
	reverted := false
	for _, it := range b["items"].([]any) {
		if cr := it.(map[string]any); cr["kind"] == "SYSTEM_REVERT" && cr["status"] == "APPLIED" {
			reverted = true
		}
	}
	if !reverted {
		t.Errorf("no applied SYSTEM_REVERT request for %s: %v", worlds[0].binding, b)
	}
	t.Logf("break-glass %s reverted by ligo at its TTL", first)

	// the others are reverted by a person: nothing is left open for the next run
	for _, id := range opened[1:] {
		if code, b := dave.req("POST", "/v1/admin/change-requests/"+id+"/revert", map[string]any{"comment": "campaign over"}); code/100 != 2 {
			t.Errorf("revert of %s: %d %v", id, code, b)
		}
	}
}

func bindingPurpose(t *testing.T, a *admin, name string) string {
	t.Helper()
	code, b := a.req("GET", "/v1/admin/bindings/"+name, nil)
	if code != http.StatusOK {
		t.Fatalf("get binding %s: %d %v", name, code, b)
	}
	if s, ok := b["purpose"].(string); ok {
		return s
	}
	spec, _ := b["spec"].(map[string]any)
	s, _ := spec["purpose"].(string)
	return s
}

// TestServeCampaignRateLimit: a principal that exceeds its rate gets 429 with
// Retry-After and the problem rate-limited; another principal is not affected
// and the first recovers.
func TestServeCampaignRateLimit(t *testing.T) {
	sam, dora := newAdmin(t, "sam"), newAdmin(t, "dora")
	const path = "/v1/admin/sources?pageSize=1"
	var mu sync.Mutex
	limited, ok := 0, 0
	var retryAfter string
	var wg sync.WaitGroup
	for range 150 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", sam.base+path, nil)
			resp, err := sam.client.Do(req)
			if err != nil {
				t.Errorf("GET: %v", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			mu.Lock()
			defer mu.Unlock()
			switch resp.StatusCode {
			case http.StatusTooManyRequests:
				limited++
				retryAfter = resp.Header.Get("Retry-After")
			case http.StatusOK:
				ok++
			default:
				t.Errorf("GET: %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if limited == 0 {
		t.Fatalf("150 concurrent requests of one principal: %d answered, none limited", ok)
	}
	if retryAfter == "" {
		t.Errorf("a 429 without Retry-After")
	}
	t.Logf("150 concurrent requests: %d answered, %d limited, Retry-After %s", ok, limited, retryAfter)
	if code, b := dora.do("GET", path, nil); code != http.StatusOK {
		t.Errorf("another principal during the burst: %d %v", code, b)
	}
	time.Sleep(3 * time.Second)
	if code, b := sam.do("GET", "/v1/admin/sources?pageSize=1&q="+url.QueryEscape("x"), nil); code != http.StatusOK {
		t.Errorf("the limited principal after 3s: %d %v", code, b)
	}
}
