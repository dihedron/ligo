//go:build lab

package serve

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/pkg/client"
)

// flowcheckStep tells lab.sh to act on ligo1 (name is "block" or "unblock",
// arg what it acts on) and waits until it has: lab.sh adds or removes a
// prohibit route, which this process, running as the workload, cannot.
func flowcheckStep(t *testing.T, name, arg string) {
	t.Helper()
	dir := e2eEnv(t, "LIGO_E2E_DIR")
	if err := os.WriteFile(filepath.Join(dir, "flowcheck-"+name), []byte(arg), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, err := os.Stat(filepath.Join(dir, "flowcheck-"+name+"-done")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lab.sh did not %s", name)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestServeClientFlowcheck: FC-L1 to FC-L5 (.specs/ligo-network-checks.md §6,
// chunk 3). A workload checks the flows of a real binding against the real
// lab servers with Client.CheckFlows: all reachable; one made unreachable
// by a route that lab.sh adds on ligo1, and only that one reported; reachable
// again once the route is gone; a denied network skipped; ICMP opt-in.
func TestServeClientFlowcheck(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	source := topologySource(t, olga, dora, "fc-src-"+x, "prod.lab", "spiffe://prod.lab/ns/e2e/sa/w"+x)
	target := topologyTarget(t, olga, dora, "fc-ledger-"+x, "pg-ledger-dynamic", "dc/corp-prod/ledger")
	binding := "fc-" + x
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	if code != 202 {
		t.Fatalf("binding: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	b := phase(t, olga, binding, "ACTIVE")
	defer revoke(t, olga, dora, binding, b)

	pem, err := os.ReadFile(e2eEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	c := sdkClient(t, client.REST)
	filter := client.Filter{Target: target}
	check := func(opts ...client.CheckOption) client.FlowResults {
		t.Helper()
		res, err := c.CheckFlows(t.Context(), filter, append([]client.CheckOption{client.WithRoots(roots), client.WithTimeout(5 * time.Second), client.WithRetries(1)}, opts...)...)
		if err != nil {
			t.Fatalf("CheckFlows: %v", err)
		}
		return res
	}

	// the binding is ACTIVE for the admin API, but the workload API may still answer without it for a moment
	deadline := time.Now().Add(30 * time.Second)
	for {
		if bf, err := c.Flows(t.Context(), filter); err == nil && len(bf) > 0 && len(bf[0].Flows) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the workload API gives no flows for an ACTIVE binding after 30s")
		}
		time.Sleep(time.Second)
	}

	// FC-L1: every flow of the binding is reachable, TLS verified against the lab CA
	res := check()
	if len(res) == 0 || !res.OK() {
		t.Fatalf("all flows reachable: %s", describe(res))
	}
	reachable := 0
	var blocked client.FlowResult
	for _, r := range res {
		if r.Binding != binding || r.Target != target {
			t.Errorf("a result of another binding: %+v", r)
		}
		if r.Status == client.Reachable {
			reachable++
			if blocked.Destination == "" && r.Port == 5432 {
				blocked = r // the target's database
			}
		}
	}
	if reachable == 0 || blocked.Destination == "" {
		t.Fatalf("no reachable flow to the database (port 5432): %s", describe(res))
	}
	t.Logf("FC-L1: %d results, %d reachable: %s", len(res), reachable, describe(res))

	// FC-L2: a prohibit route to the database host, and only its flow is reported
	flowcheckStep(t, "block", blocked.Destination)
	res = check()
	un := res.Unreachable()
	if res.OK() || len(un) == 0 {
		t.Fatalf("with the route, nothing is unreachable: %s", describe(res))
	}
	for _, r := range un {
		if r.Destination != blocked.Destination || r.Err == nil {
			t.Errorf("an unexpected unreachable result: %+v", r)
		}
	}
	if len(un) == len(res) {
		t.Errorf("every flow is unreachable, the block was meant to hit one host: %s", describe(res))
	}
	t.Logf("FC-L2: %s", describe(res))

	// FC-L3: the route removed, everything is reachable again
	flowcheckStep(t, "unblock", blocked.Destination)
	if res = check(); !res.OK() {
		t.Errorf("after the route is gone: %s", describe(res))
	}

	// FC-L4: the cloud metadata address is denied by default, and no packet goes out
	flows := []client.BindingFlows{{Binding: binding, Target: target, Flows: []client.Flow{
		{Name: "metadata", Protocol: "TCP", Destination: "169.254.169.254", Ports: []client.PortRange{{Low: 80, High: 80}}},
	}}}
	denied, err := client.CheckFlowData(t.Context(), flows)
	if err != nil || len(denied) != 1 || denied[0].Status != client.Skipped || !strings.Contains(denied[0].Reason, "denied") {
		t.Errorf("a denied network: %+v (%v)", denied, err)
	}

	// FC-L5: ICMP is opt-in; either the host may ping or the reason names what is missing
	icmp := check(client.WithICMP(false))
	extra := 0
	for _, r := range icmp {
		if r.Protocol != "icmp" {
			continue
		}
		extra++
		if r.Status == client.Unreachable && !errors.Is(r.Err, os.ErrPermission) && !strings.Contains(r.Reason, "cap_net_raw") && !strings.Contains(r.Reason, "ping_group_range") {
			t.Errorf("an ICMP result without a reason that names the capability: %+v", r)
		}
	}
	if extra == 0 {
		t.Errorf("WithICMP added no check: %s", describe(icmp))
	}
	t.Logf("FC-L5: %d ICMP results: %s", extra, describe(icmp))
}

// describe lists results for a failure message: no secrets are in them.
func describe(res client.FlowResults) string {
	var b strings.Builder
	for _, r := range res {
		b.WriteString("\n  ")
		b.WriteString(r.Flow + " " + r.Destination + " " + r.Protocol + " " + string(r.Status) + " " + r.Reason)
		if r.Err != nil {
			b.WriteString(" (" + r.Err.Error() + ")")
		}
	}
	return b.String()
}
