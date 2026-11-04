//go:build lab

package serve

import (
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The HA e2e of ligo serve on ligo1 and ligo2, run by lab.sh serve test-ha,
// which stops and starts the replicas between the tests
// (.specs/ligo-test-environment.md, "The HA tests"). LIGO_E2E_ADMIN is
// ligo1's admin listener, LIGO_E2E_ADMIN2 ligo2's, LIGO_E2E_WORKLOAD ligo2's
// workload listener.

// on2 is who's admin client of ligo2.
func on2(t *testing.T, who string) *admin {
	t.Helper()
	a := newAdmin(t, who)
	a.base = e2eEnv(t, "LIGO_E2E_ADMIN2")
	return a
}

// slug is a problem answer's slug.
func slug(body map[string]any) string {
	s, _ := body["type"].(string)
	return strings.TrimPrefix(s, "urn:ligo:problem:")
}

// filedCR is the change request of a filed answer, which must be 202.
func filedCR(t *testing.T, what string, code int, body map[string]any) map[string]any {
	t.Helper()
	cr, _ := body["changeRequest"].(map[string]any)
	if code != http.StatusAccepted || cr == nil {
		t.Fatalf("%s: %d %v", what, code, body)
	}
	return cr
}

// approve approves one side of a change request and returns the answer.
func approve(a *admin, cr map[string]any, side string) (int, map[string]any) {
	return a.do("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve",
		map[string]any{"payloadSha256": cr["payloadSha256"], "side": side, "comment": "ha e2e"})
}

// awaiting is the sides of a change request still awaiting a decision.
func awaiting(cr map[string]any) []string {
	var out []string
	for _, s := range cr["awaitingApproval"].([]any) {
		out = append(out, s.(string))
	}
	return out
}

// approveBut approves, through a, every side of cr but the last, and
// returns the request with that one side left.
func approveBut(t *testing.T, a *admin, cr map[string]any) map[string]any {
	t.Helper()
	for sides := awaiting(cr); len(sides) > 1; sides = awaiting(cr) {
		code, body := approve(a, cr, sides[0])
		if code != http.StatusOK {
			t.Fatalf("approve %s: %d %v", sides[0], code, body)
		}
		cr = body["changeRequest"].(map[string]any)
	}
	return cr
}

// haFixture registers, through a, a source of the one SPIFFE ID
// w<tag><suffix> (the lab's ligo-plugin-vault binds literal IDs only) and a target
// on pg-ledger whose level read grants both ledger roles, both approved by
// dora.
func haFixture(t *testing.T, olga, dora *admin, tag string) (source, target string) {
	t.Helper()
	x := tag + e2eEnv(t, "LIGO_E2E_SUFFIX")
	source, target = "ha-src-"+x, "ha-ledger-"+x
	code, filed := olga.do("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": source},
		"identity": map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/ha/sa/w` + x + `$`,
			"sampleSpiffeIds": []string{"spiffe://prod.lab/ns/ha/sa/w" + x}}, "visibility": map[string]string{"mode": "PRIVATE"}})
	filedCR(t, "source", code, filed)
	approveAll(t, dora, filed)
	code, filed = olga.do("POST", "/v1/admin/targets", haTarget(target, "LEDGER_RO_ROLE", "LEDGER_RW_ROLE"))
	filedCR(t, "target", code, filed)
	approveAll(t, dora, filed)
	return source, target
}

// haTarget is the body of the target name on pg-ledger whose level read
// grants roles.
func haTarget(name string, roles ...string) map[string]any {
	return map[string]any{"kind": "Target",
		"metadata":     map[string]string{"name": name, "platform": "pg-ledger", "scope": "dc/corp-prod/ledger"},
		"definition":   map[string]string{"database": "ledger", "schema": "ledger"},
		"accessLevels": []any{map[string]any{"name": "read", "grants": map[string][]string{"roles": roles}}},
		"visibility":   map[string]string{"mode": "PRIVATE"}}
}

// TestServeHAMaintenance (AC-26): maintenance turned on through ligo1
// refuses a change on ligo2 and an approval on ligo1; the workload API keeps
// serving; inFlight falls to 0; turned off through ligo2, the approval goes
// through.
func TestServeHAMaintenance(t *testing.T) {
	ada, ada2, olga, olga2, dora := newAdmin(t, "ada"), on2(t, "ada"), newAdmin(t, "olga"), on2(t, "olga"), newAdmin(t, "dora")
	x := "m" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	source := func(name string) map[string]any {
		return map[string]any{"kind": "Source", "metadata": map[string]string{"name": name},
			"identity":   map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/ha/sa/` + name + `$`},
			"visibility": map[string]string{"mode": "PRIVATE"}}
	}
	code, filed := olga.do("POST", "/v1/admin/sources", source("ha-src-"+x))
	pending := filedCR(t, "source before maintenance", code, filed)

	if code, body := ada.do("PUT", "/v1/admin/maintenance", map[string]any{"enabled": true, "reason": "ha e2e AC-26"}); code != http.StatusOK || body["maintenanceMode"] != true {
		t.Fatalf("maintenance on through ligo1: %d %v", code, body)
	}
	t.Cleanup(func() { ada2.do("PUT", "/v1/admin/maintenance", map[string]any{"enabled": false}) })
	if code, body := olga2.do("POST", "/v1/admin/sources", source("ha-src2-"+x)); code != http.StatusServiceUnavailable || slug(body) != "maintenance" {
		t.Errorf("a change through ligo2: %d %v", code, body)
	}
	if code, body := approve(dora, pending, awaiting(pending)[0]); code != http.StatusServiceUnavailable || slug(body) != "maintenance" {
		t.Errorf("an approval through ligo1: %d %v", code, body)
	}
	if code, _, body := newWorkload(t, "workload", false).get("/v1/bindings", ""); code != http.StatusOK {
		t.Errorf("the workload API on ligo2: %d %v", code, body)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		code, body := olga2.do("GET", "/v1/admin/maintenance", nil)
		if code == http.StatusOK && body["maintenanceMode"] == true && body["inFlight"] == float64(0) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("maintenance status on ligo2: %d %v", code, body)
		}
		time.Sleep(time.Second)
	}

	if code, body := ada2.do("PUT", "/v1/admin/maintenance", map[string]any{"enabled": false}); code != http.StatusOK || body["maintenanceMode"] != false {
		t.Fatalf("maintenance off through ligo2: %d %v", code, body)
	}
	approveAll(t, dora, filed)
}

// TestServeHAConcurrentApproval (AC-50): dora (TARGET, through ligo1) and
// sam (SOURCE, through ligo2) approve a binding's two sides at the same
// moment: it is applied exactly once, with one workflow.
func TestServeHAConcurrentApproval(t *testing.T) {
	olga, dora, dora2, sam2 := newAdmin(t, "olga"), newAdmin(t, "dora"), on2(t, "dora"), on2(t, "sam")
	source, target := haFixture(t, olga, dora, "c")
	binding := "ha-c-" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	cr := filedCR(t, "binding", code, filed)
	if got := strings.Join(awaiting(cr), " "); got != "SOURCE TARGET" && got != "TARGET SOURCE" {
		t.Fatalf("sides awaiting: %s", got)
	}
	var wg sync.WaitGroup
	codes, bodies := make([]int, 2), make([]map[string]any, 2)
	start := make(chan struct{})
	for i, ap := range []struct {
		a    *admin
		side string
	}{{dora, "TARGET"}, {sam2, "SOURCE"}} {
		wg.Go(func() {
			<-start
			codes[i], bodies[i] = approve(ap.a, cr, ap.side)
		})
	}
	close(start)
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("approval %d: %d %v", i, code, bodies[i])
		}
	}
	if code, body := dora2.do("GET", "/v1/admin/change-requests/"+cr["id"].(string), nil); code != http.StatusOK || body["status"] != "APPLIED" {
		t.Fatalf("the request after both approvals: %d %v", code, body)
	}
	b := phase(t, on2(t, "olga"), binding, "ACTIVE")
	if st := b["status"].(map[string]any); st["attempt"] != float64(1) {
		t.Errorf("attempts: %v", st["attempt"])
	}
}

// TestServeHARetireRace (AC-77): a binding CREATE and the retirement of its
// target, approved at the same moment on ligo1 and ligo2: exactly one wins.
func TestServeHARetireRace(t *testing.T) {
	olga, dora, dora2 := newAdmin(t, "olga"), newAdmin(t, "dora"), on2(t, "dora")
	source, target := haFixture(t, olga, dora, "r")
	binding := "ha-r-" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	bcr := approveBut(t, dora, filedCR(t, "binding", code, filed))
	_, tg := olga.do("GET", "/v1/admin/targets/"+target, nil)
	code, filed = olga.do("POST", "/v1/admin/targets/"+target+"/retire", map[string]any{"expectedRevision": tg["metadata"].(map[string]any)["revision"]})
	rcr := approveBut(t, dora2, filedCR(t, "retire", code, filed))

	var wg sync.WaitGroup
	var bcode, rcode int
	var bbody, rbody map[string]any
	start := make(chan struct{})
	wg.Go(func() { <-start; bcode, bbody = approve(dora, bcr, awaiting(bcr)[0]) })
	wg.Go(func() { <-start; rcode, rbody = approve(dora2, rcr, awaiting(rcr)[0]) })
	close(start)
	wg.Wait()
	status := func(body map[string]any) string {
		cr, _ := body["changeRequest"].(map[string]any)
		s, _ := cr["status"].(string)
		return s
	}
	bound := bcode == http.StatusOK && status(bbody) == "APPLIED"
	retired := rcode == http.StatusOK && status(rbody) == "APPLIED"
	switch {
	case bound && !retired:
		if rcode != http.StatusConflict || slug(rbody) != "resource-in-use" {
			t.Errorf("the binding won, the retirement got %d %v", rcode, rbody)
		}
		phase(t, olga, binding, "ACTIVE")
	case retired && !bound:
		if bcode != http.StatusConflict || slug(bbody) != "resource-deprecated" {
			t.Errorf("the retirement won, the binding got %d %v", bcode, bbody)
		}
		if code, _ := olga.do("GET", "/v1/admin/bindings/"+binding, nil); code != http.StatusNotFound {
			t.Errorf("the binding exists: %d", code)
		}
	default:
		t.Fatalf("not exactly one winner: binding %d %v, retirement %d %v", bcode, bbody, rcode, rbody)
	}
	t.Logf("winner: binding %t, retirement %t", bound, retired)
}

// TestServeHAAloneFile: with ligo1 stopped, olga files a source through
// ligo2 and leaves it pending; lab.sh then makes it due, and ligo2's sweeper
// expires it.
func TestServeHAAloneFile(t *testing.T) {
	name := "ha-exp-" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	code, filed := on2(t, "olga").do("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": name},
		"identity":   map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/ha/sa/` + name + `$`},
		"visibility": map[string]string{"mode": "PRIVATE"}})
	filedCR(t, "source", code, filed)
}

// TestServeHAAloneApply: with ligo1 stopped, ligo2 alone applies a binding
// (its workflow) and propagates a narrowing of its target's level (the
// propagator, priority 0).
func TestServeHAAloneApply(t *testing.T) {
	olga, dora := on2(t, "olga"), on2(t, "dora")
	source, target := haFixture(t, olga, dora, "a")
	binding := "ha-a-" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	filedCR(t, "binding", code, filed)
	approveAll(t, dora, filed)
	before := phase(t, olga, binding, "ACTIVE")["active"].(map[string]any)

	_, tg := olga.do("GET", "/v1/admin/targets/"+target, nil)
	narrowed := haTarget(target, "LEDGER_RO_ROLE")
	narrowed["expectedRevision"] = tg["metadata"].(map[string]any)["revision"]
	code, filed = olga.do("PUT", "/v1/admin/targets/"+target, narrowed)
	filedCR(t, "narrowing", code, filed)
	approveAll(t, dora, filed)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		b := phase(t, olga, binding, "ACTIVE")
		active, _ := b["active"].(map[string]any)
		if active != nil && active["revision"] != before["revision"] {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the narrowing was not propagated: %v", b["active"])
		}
		time.Sleep(time.Second)
	}
}

// TestServeHAKill: ligo1 starts a binding's apply and freezes (SIGSTOP)
// right after; for longer than the sweeper's stale threshold and one sweep,
// ligo2 leaves the workflow to its executor (§10.2): the binding stays
// PROVISIONING. Killed, ligo1 is restarted by systemd under the same
// instance ID, recovers its workflow, and the binding becomes ACTIVE.
func TestServeHAKill(t *testing.T) {
	olga, dora, olga2 := newAdmin(t, "olga"), newAdmin(t, "dora"), on2(t, "olga")
	source, target := haFixture(t, olga, dora, "k")
	binding := "ha-k-" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	out, err := exec.Command("pgrep", "-x", "ligo").Output()
	if err != nil {
		t.Fatalf("pgrep ligo: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("ligo's pid %q: %v", out, err)
	}
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	cr := approveBut(t, dora, filedCR(t, "binding", code, filed))
	if code, body := approve(dora, cr, awaiting(cr)[0]); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, body)
	}
	if err := exec.Command("kill", "-STOP", strconv.Itoa(pid)).Run(); err != nil {
		t.Fatalf("SIGSTOP ligo1: %v", err)
	}
	stopped := true
	t.Cleanup(func() {
		if stopped {
			_ = exec.Command("kill", "-KILL", strconv.Itoa(pid)).Run()
		}
	})
	for end := time.Now().Add(100 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Second) {
		code, b := olga2.do("GET", "/v1/admin/bindings/"+binding, nil)
		if st, _ := b["status"].(map[string]any); code != http.StatusOK || st["phase"] != "PROVISIONING" {
			t.Fatalf("with ligo1 frozen, ligo2 shows the binding %d %v", code, st)
		}
	}
	if err := exec.Command("kill", "-KILL", strconv.Itoa(pid)).Run(); err != nil {
		t.Fatalf("SIGKILL ligo1: %v", err)
	}
	stopped = false
	phase(t, olga2, binding, "ACTIVE")
}

// TestServeHARecoverFrozen: with ligo1 frozen (SIGSTOP) in a binding's apply,
// its sessions are alive, and ligo2 refuses to recover it (§10.2). It leaves
// ligo1 frozen, for lab.sh to cut its power and recover it with the CLI.
func TestServeHARecoverFrozen(t *testing.T) {
	olga, dora, ada2 := newAdmin(t, "olga"), newAdmin(t, "dora"), on2(t, "ada")
	source, target := haFixture(t, olga, dora, "g")
	binding := "ha-g-" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	out, err := exec.Command("pgrep", "-x", "ligo").Output()
	if err != nil {
		t.Fatalf("pgrep ligo: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("ligo's pid %q: %v", out, err)
	}
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	cr := approveBut(t, dora, filedCR(t, "binding", code, filed))
	if code, body := approve(dora, cr, awaiting(cr)[0]); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, body)
	}
	if err := exec.Command("kill", "-STOP", strconv.Itoa(pid)).Run(); err != nil {
		t.Fatalf("SIGSTOP ligo1: %v", err)
	}
	code, body := ada2.do("GET", "/v1/admin/executors", nil)
	if code != http.StatusOK || executor(body, "ligo1")["pending"] == 0.0 || executor(body, "ligo1")["liveSessions"] == 0.0 {
		t.Fatalf("executors with ligo1 frozen: %d %v", code, body)
	}
	if code, body := ada2.do("POST", "/v1/admin/executors/ligo1/recover", nil); code != http.StatusConflict || body["type"] != "urn:ligo:problem:executor-alive" {
		t.Fatalf("recovering a frozen replica: %d %v", code, body)
	}
	if code, body := ada2.do("POST", "/v1/admin/executors/ligo2/recover", nil); code != http.StatusConflict || body["type"] != "urn:ligo:problem:executor-self" {
		t.Fatalf("recovering itself: %d %v", code, body)
	}
}

// executor is an executor's row with pending workflows in GET
// /v1/admin/executors.
func executor(body map[string]any, id string) map[string]any {
	items, _ := body["items"].([]any)
	for _, it := range items {
		if row, _ := it.(map[string]any); row["executor"] == id {
			return row
		}
	}
	return map[string]any{"pending": 0.0, "liveSessions": 0.0}
}
