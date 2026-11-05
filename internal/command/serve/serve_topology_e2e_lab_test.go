//go:build lab

package serve

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// topologySource registers, as who and approved by approver, a public source
// of one SPIFFE ID, and returns its name.
func topologySource(t *testing.T, who, approver *admin, name, trustDomain, id string) string {
	t.Helper()
	code, filed := who.do("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": name},
		"identity":   map[string]any{"trustDomain": trustDomain, "svidRegex": "^" + strings.ReplaceAll(id, ".", `\.`) + "$", "sampleSpiffeIds": []string{id}},
		"visibility": map[string]string{"mode": "PUBLIC"}})
	if code != http.StatusAccepted && code != http.StatusOK {
		t.Fatalf("source %s: %d %v", name, code, filed)
	}
	approveAll(t, approver, filed)
	return name
}

// topologyTarget publishes, as who, a public target on platform in scope.
func topologyTarget(t *testing.T, who, approver *admin, name, platform, scope string) string {
	t.Helper()
	code, filed := who.do("POST", "/v1/admin/targets", map[string]any{"kind": "Target",
		"metadata":     map[string]string{"name": name, "platform": platform, "scope": scope},
		"definition":   map[string]string{"database": "ledger", "schema": "ledger"},
		"accessLevels": []any{map[string]any{"name": "read", "grants": map[string][]string{"roles": {"LEDGER_RO_ROLE"}}}},
		"networkFlows": []any{map[string]any{"name": "ledger", "purpose": "DATA", "protocol": "TCP", "destination": "pg.ligo.lab",
			"ports": []int{5432}, "tls": true, "serverName": "pg.ligo.lab"}},
		"visibility": map[string]string{"mode": "PUBLIC"}})
	if code != http.StatusAccepted && code != http.StatusOK {
		t.Fatalf("target %s: %d %v", name, code, filed)
	}
	approveAll(t, approver, filed)
	return name
}

// decide approves each side of a filed request with its own person.
func decide(t *testing.T, filed map[string]any, people map[string]*admin) {
	t.Helper()
	cr, _ := filed["changeRequest"].(map[string]any)
	if cr == nil {
		t.Fatalf("no change request: %v", filed)
	}
	for cr["status"] == "PENDING" {
		awaiting, _ := cr["awaitingApproval"].([]any)
		if len(awaiting) == 0 {
			t.Fatalf("pending with no side awaiting: %v", cr)
		}
		side := fmt.Sprint(awaiting[0])
		who := people[side]
		if who == nil {
			t.Fatalf("nobody decides side %s", side)
		}
		code, body := who.do("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve",
			map[string]any{"payloadSha256": cr["payloadSha256"], "side": side, "comment": "e2e"})
		if code != http.StatusOK {
			t.Fatalf("approve %s: %d %v", side, code, body)
		}
		cr = body["changeRequest"].(map[string]any)
	}
	if cr["status"] != "APPLIED" {
		t.Fatalf("change request %s: %v", cr["status"], cr)
	}
}

// sideNames lists the sides of a filed request, sorted.
func sideNames(filed map[string]any) []string {
	var out []string
	cr, _ := filed["changeRequest"].(map[string]any)
	sides, _ := cr["sides"].([]any)
	for _, s := range sides {
		out = append(out, s.(map[string]any)["side"].(string))
	}
	slices.Sort(out)
	return out
}

// TestServeTopologies: the four topologies of ADR-13, each filed from one side
// and approved by each owner, its workload served and then revoked; the workload
// from a tenancy is in test.lab, whose scope comes from its SPIFFE path. The
// pair no rule allows is refused (ADR-14).
func TestServeTopologies(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	olga, dora, paula, pia, hana, sean, ada := newAdmin(t, "olga"), newAdmin(t, "dora"), newAdmin(t, "paula"), newAdmin(t, "pia"),
		newAdmin(t, "hana"), newAdmin(t, "sean"), newAdmin(t, "ada")

	dc := topologySource(t, olga, dora, "topo-dc-"+x, "prod.lab", "spiffe://prod.lab/ns/topo/sa/w"+x)
	cloud := topologySource(t, paula, pia, "topo-cloud-"+x, "test.lab", "spiffe://test.lab/acct/fin-01/tenant/payments/ns/topo/sa/w"+x)
	if code, b := ada.do("GET", "/v1/admin/sources/"+cloud, nil); code != http.StatusOK || b["metadata"].(map[string]any)["scope"] != "cloud/fin-01/payments" {
		t.Fatalf("the tenancy's source: %d %v", code, b)
	}
	ledger := topologyTarget(t, olga, dora, "topo-ledger-"+x, "pg-ledger", "dc/corp-prod/ledger")
	hr := topologyTarget(t, hana, hana, "topo-hr-"+x, "pg-ledger-cloud", "cloud/fin-01/hr")

	for _, tc := range []struct {
		name, source, target, load string
		filer                      *admin
		sides                      []string
		people                     map[string]*admin
	}{
		{"cloud-to-cloud", cloud, hr, "cloudload", paula, []string{"SOURCE", "TARGET"}, map[string]*admin{"SOURCE": pia, "TARGET": hana}},
		{"dc-to-dc", dc, ledger, "dcload", olga, []string{"SOURCE", "TARGET"}, map[string]*admin{"SOURCE": dora, "TARGET": dora}},
		{"cloud-to-dc", cloud, ledger, "cloudload", paula, []string{"PARTY:security", "SOURCE", "TARGET"},
			map[string]*admin{"SOURCE": pia, "TARGET": dora, "PARTY:security": sean}},
		{"dc-to-cloud", dc, hr, "dcload", olga, []string{"SOURCE", "TARGET"}, map[string]*admin{"SOURCE": dora, "TARGET": hana}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := "topo-" + tc.name + "-" + x
			code, filed := tc.filer.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": tc.source, "target": tc.target, "accessLevel": "read"})
			if code != http.StatusAccepted {
				t.Fatalf("file: %d %v", code, filed)
			}
			if got := sideNames(filed); !slices.Equal(got, tc.sides) {
				t.Errorf("sides %v, want %v", got, tc.sides)
			}
			decide(t, filed, tc.people)
			b := phase(t, ada, binding, "ACTIVE")

			w := newWorkload(t, tc.load, false)
			var list []map[string]any
			for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(500 * time.Millisecond) {
				code, _, body := w.get("/v1/bindings?target="+tc.target, "")
				if list = items(body); code == http.StatusOK && len(list) == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the workload does not receive the binding: %d %v", code, body)
				}
			}
			if list[0]["name"] != binding {
				t.Errorf("the workload receives %v", list[0]["name"])
			}

			revision := int64(b["metadata"].(map[string]any)["revision"].(float64))
			code, filed = tc.filer.do("DELETE", fmt.Sprintf("/v1/admin/bindings/%s?expectedRevision=%d", binding, revision), nil)
			if code != http.StatusAccepted {
				t.Fatalf("revoke: %d %v", code, filed)
			}
			decide(t, filed, tc.people) // consent ANY: one side of the filer's is enough
			phase(t, ada, binding, "")
			if code, _, body := w.get("/v1/bindings?target="+tc.target, ""); code != http.StatusOK || len(items(body)) != 0 {
				t.Errorf("after the revocation: %d %v", code, body)
			}
		})
	}

	other := topologySource(t, ada, sean, "topo-other-"+x, "test.lab", "spiffe://test.lab/acct/fin-02/tenant/sales/ns/topo/sa/w"+x)
	code, body := ada.do("POST", "/v1/admin/bindings", map[string]any{"name": "topo-denied-" + x, "source": other, "target": hr, "accessLevel": "read"})
	if code != http.StatusForbidden || !strings.Contains(fmt.Sprint(body["type"]), "interconnect-denied") {
		t.Errorf("another account's source: %d %v", code, body)
	}
}
