//go:build lab

package serve

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// faultFixture creates the source and the target of the faults' bindings.
func faultFixture(t *testing.T, olga, dora *admin) (source, target string) {
	t.Helper()
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	source, target = "fault-src-"+x, "fault-ledger-"+x
	if code, _ := olga.do("GET", "/v1/admin/sources/"+source, nil); code == http.StatusOK {
		return source, target
	}
	topologySource(t, olga, dora, source, "prod.lab", "spiffe://prod.lab/ns/fault/sa/w"+x)
	topologyTarget(t, olga, dora, target, "pg-ledger", "dc/corp-prod/ledger")
	return source, target
}

// TestServeFaultWarm: a binding applied, so that the plugin holds its
// credential when the secrets backend stops, and only sealing can fail.
func TestServeFaultWarm(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	source, target := faultFixture(t, olga, dora)
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": "fault-warm-" + e2eEnv(t, "LIGO_E2E_SUFFIX"), "source": source, "target": target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		t.Fatalf("file: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	phase(t, olga, "fault-warm-"+e2eEnv(t, "LIGO_E2E_SUFFIX"), "ACTIVE")
}

// TestServeFaultTransitDown: AC-09, the secrets backend is stopped: the
// attempt fails with SEALED_SECRET_UNAVAILABLE, not silently and not for ever.
func TestServeFaultTransitDown(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	_, target := faultFixture(t, olga, dora)
	name := "fault-seal-" + e2eEnv(t, "LIGO_E2E_SUFFIX")
	source := topologySource(t, olga, dora, name+"-src", "prod.lab", "spiffe://prod.lab/ns/fault/sa/s"+e2eEnv(t, "LIGO_E2E_SUFFIX"))
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": name, "source": source, "target": target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		t.Fatalf("file: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(2 * time.Second) {
		code, b := olga.do("GET", "/v1/admin/bindings/"+name, nil)
		st, _ := b["status"].(map[string]any)
		if code == http.StatusOK && st["phase"] == "FAILED" {
			if !strings.HasPrefix(fmt.Sprint(st["message"]), "SEALED_SECRET_UNAVAILABLE") {
				t.Fatalf("failed with %v", st)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("binding %s: %d %v", name, code, st)
		}
	}
}

// TestServeFaultTransitBack: AC-09, the backend is back: a retry is a new
// attempt, which rotates and succeeds. The two bindings are then revoked.
func TestServeFaultTransitBack(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	name := "fault-seal-" + x
	if code, body := olga.do("POST", "/v1/admin/bindings/"+name+"/retry", nil); code != http.StatusAccepted {
		t.Fatalf("retry: %d %v", code, body)
	}
	b := phase(t, olga, name, "ACTIVE")
	revoke(t, olga, dora, name, b)
	revoke(t, olga, dora, "fault-warm-"+x, phase(t, olga, "fault-warm-"+x, "ACTIVE"))
}

// TestServeFaultDatabase: PostgreSQL stops while lab.sh watches bindings being
// provisioned, and returns: every binding converges, without anyone's help,
// and a new one is applied through each replica.
func TestServeFaultDatabase(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	dora.base = e2eEnv(t, "LIGO_E2E_ADMIN2")
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	_, target := faultFixture(t, olga, dora)

	const n = 8
	filed := make([]map[string]any, n)
	name := func(i int) string { return fmt.Sprintf("fdb-%s-%d", x, i) }
	for i := range n {
		source := topologySource(t, olga, dora, name(i)+"-src", "prod.lab", fmt.Sprintf("spiffe://prod.lab/ns/fdb/sa/w%s-%d", x, i))
		code, f := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": name(i), "source": source, "target": target, "accessLevel": "read"})
		if code != http.StatusAccepted {
			t.Fatalf("file %d: %d %v", i, code, f)
		}
		filed[i] = f
	}
	var wg sync.WaitGroup
	for _, f := range filed {
		wg.Go(func() { approveThrough(t, dora, f) })
	}
	wg.Wait()
	for i := range n {
		phase(t, olga, name(i), "ACTIVE")
	}
	// a new binding through each replica: the service works again
	for i, a := range []*admin{dora, newAdmin(t, "dora")} {
		source := topologySource(t, olga, dora, fmt.Sprintf("fdb-%s-new%d-src", x, i), "prod.lab", fmt.Sprintf("spiffe://prod.lab/ns/fdb/sa/n%s-%d", x, i))
		binding := fmt.Sprintf("fdb-%s-new%d", x, i)
		code, f := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
		if code != http.StatusAccepted {
			t.Fatalf("file: %d %v", code, f)
		}
		approveAll(t, a, f)
		phase(t, olga, binding, "ACTIVE")
	}
}

// approveThrough approves every side, again and again while the database is
// away: an answer of 5xx says nothing about the request.
func approveThrough(t *testing.T, dora *admin, filed map[string]any) {
	t.Helper()
	cr, _ := filed["changeRequest"].(map[string]any)
	if cr == nil {
		t.Errorf("no change request: %v", filed)
		return
	}
	id := cr["id"].(string)
	for deadline := time.Now().Add(3 * time.Minute); cr["status"] == "PENDING"; {
		awaiting, _ := cr["awaitingApproval"].([]any)
		if len(awaiting) == 0 {
			t.Errorf("pending with no side awaiting: %v", cr)
			return
		}
		code, body := dora.do("POST", "/v1/admin/change-requests/"+id+"/approve",
			map[string]any{"payloadSha256": cr["payloadSha256"], "side": awaiting[0], "comment": "e2e"})
		if code == http.StatusOK {
			cr = body["changeRequest"].(map[string]any)
			continue
		}
		if time.Now().After(deadline) {
			t.Errorf("approve: %d %v", code, body)
			return
		}
		time.Sleep(time.Second)
		if code, body := dora.do("GET", "/v1/admin/change-requests/"+id, nil); code == http.StatusOK {
			cr = body
		}
	}
}
