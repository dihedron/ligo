//go:build lab

package serve

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The Python SDK's lab tests (.specs/ligo-client-sdk-python.md, PY-L2 and PY-L3). The tests file and approve
// the bindings as the Go ones do, and run the helper of test/lab/python (lab.sh installs it on ligo1, with
// ligo-client in a venv) as the workload; the helper prints what the SDK saw as JSON, and these tests judge it.

const (
	pythonBin    = "/opt/ligo-py/bin/python"
	pythonHelper = "/usr/local/lib/ligo-lab/sdk_check.py"
)

// pyBinding is a binding as the helper prints it.
type pyBinding struct {
	Name        string            `json:"name"`
	Target      string            `json:"target"`
	Strategy    string            `json:"strategy"`
	Endpoint    string            `json:"endpoint"`
	Description string            `json:"description"`
	Annotations map[string]string `json:"annotations"`
}

type pyCredential struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	Expires  float64 `json:"expires"`
}

// pyEvent is one line of `sdk_check.py watch`.
type pyEvent struct {
	Kind       string        `json:"kind"`
	Binding    *pyBinding    `json:"binding"`
	Previous   *pyBinding    `json:"previous"`
	Credential *pyCredential `json:"credential"`
	Error      string        `json:"error"`
	Count      int           `json:"count"`
	Flows      int           `json:"flows"`
}

type pyResult struct {
	Binding     string `json:"binding"`
	Target      string `json:"target"`
	Flow        string `json:"flow"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Error       string `json:"error"`
}

// pyRun runs the helper with args and waits for it; stdout is its JSON, which holds credentials, so it is
// never printed.
func pyRun(t *testing.T, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, pythonBin, append([]string{pythonHelper}, args...)...).Output() //nolint:gosec // a lab path
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("sdk_check.py %v: %v\n%s", args, err, stderr)
	}
	return out
}

// pyResults runs a helper command that prints {"results": [...]}.
func pyResults(t *testing.T, args ...string) []pyResult {
	t.Helper()
	var doc struct {
		Results []pyResult `json:"results"`
	}
	if err := json.Unmarshal(pyRun(t, args...), &doc); err != nil {
		t.Fatalf("sdk_check.py %v: %v", args, err)
	}
	return doc.Results
}

func describePy(res []pyResult) string {
	var b strings.Builder
	for _, r := range res {
		b.WriteString(fmt.Sprintf("\n  %s %s:%d %s %s %s (%s)", r.Flow, r.Destination, r.Port, r.Protocol, r.Status, r.Reason, r.Error))
	}
	return b.String()
}

// TestServeClientSDKPython: PY-L2, the Python SDK's counterpart of TestServeClientSDK. A workload that
// watches with ligo-client sees a vault-dynamic binding appear, with the operator's text, and receives a
// credential that connects; it reads a second one and the flows; at two thirds of the lease it receives a
// new one; once the binding is revoked the watch reports it, a new credential is refused and the old ones
// are gone.
func TestServeClientSDKPython(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	source := topologySource(t, olga, dora, "pysdk-src-"+x, "prod.lab", "spiffe://prod.lab/ns/e2e/sa/w"+x)
	target := topologyTarget(t, olga, dora, "pysdk-ledger-"+x, "pg-ledger-dynamic", "dc/corp-prod/ledger")
	binding := "pysdk-" + x

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonBin, pythonHelper, "watch", "--target", target) //nolint:gosec // a lab path
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	events := make(chan pyEvent, 32)
	go func() {
		defer close(events)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var ev pyEvent
			if json.Unmarshal(sc.Bytes(), &ev) == nil {
				events <- ev
			}
		}
	}()
	next := func(want string) pyEvent {
		t.Helper()
		deadline := time.After(120 * time.Second)
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					t.Fatalf("the helper ended before the %s event", want)
				}
				if ev.Kind == "credential_rotated" && want != "credential_rotated" {
					continue // a lease ran on while the test did something else
				}
				if ev.Kind != want {
					t.Fatalf("event %s, want %s", ev.Kind, want)
				}
				return ev
			case <-deadline:
				t.Fatalf("no %s event after 120s", want)
				return pyEvent{}
			}
		}
	}

	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read",
		"description": "Python SDK lab binding", "annotations": map[string]any{"change": "CHG0012345"}})
	if code != http.StatusAccepted {
		t.Fatalf("binding: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	b := phase(t, olga, binding, "ACTIVE")

	added := next("added")
	if ab := added.Binding; ab == nil || ab.Name != binding || ab.Target != target || ab.Strategy != "vault-dynamic" || ab.Endpoint == "" {
		t.Errorf("added: %+v", ab)
	} else if ab.Description != "Python SDK lab binding" || ab.Annotations["change"] != "CHG0012345" {
		t.Errorf("description %q annotations %v", ab.Description, ab.Annotations) // the text reaches the Python workload too
	}
	cred := next("credential_rotated").Credential
	if cred == nil {
		t.Fatal("a rotated event without a credential")
	}
	// the platform's credential_ttl, 90s, not the hour of plugins.dynamic_credentials
	if lease := time.Until(time.Unix(int64(cred.Expires), 0)); lease < time.Minute-5*time.Second || lease > 90*time.Second {
		t.Errorf("the credential expires in %s", lease)
	}
	record(t, cred.Password)
	reads(t, cred.Username, cred.Password)

	second := next("second_credential").Credential
	if second == nil || second.Username == cred.Username {
		t.Fatalf("a second credential: %+v", second)
	}
	record(t, second.Password)
	reads(t, second.Username, second.Password)
	if fl := next("flows"); fl.Count != 1 || fl.Flows == 0 {
		t.Errorf("flows: %+v", fl)
	}

	// at two thirds of the lease the watch reads a new credential, which connects
	started := time.Now()
	renewed := next("credential_rotated").Credential
	if renewed == nil || renewed.Username == cred.Username || time.Since(started) > 80*time.Second {
		t.Fatalf("the renewed credential after %s: %+v", time.Since(started), renewed)
	}
	record(t, renewed.Password)
	reads(t, renewed.Username, renewed.Password)

	revoke(t, olga, dora, binding, b)
	if gone := next("removed"); gone.Previous == nil || gone.Previous.Name != binding {
		t.Errorf("removed: %+v", gone.Previous)
	}
	if refused := next("refused"); refused.Error != "StoreError" {
		t.Errorf("a credential of a revoked binding: %q", refused.Error)
	}
	if after := next("bindings_after"); after.Count != 0 {
		t.Errorf("after the revocation: %d bindings", after.Count)
	}
	for _, c := range []*pyCredential{cred, second, renewed} {
		if conn, err := ledgerConn(t, c.Username, c.Password); err == nil {
			_ = conn.Close(context.Background())
			t.Errorf("the credential %s of a revoked binding still connects", c.Username)
		}
	}
}

// TestServeClientFlowcheckPython: PY-L3, the flow scenario of TestServeClientFlowcheck (FC-L1 to FC-L4) with
// ligo-client's check_flows. ICMP is not part of the Python SDK.
func TestServeClientFlowcheckPython(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	source := topologySource(t, olga, dora, "pyfc-src-"+x, "prod.lab", "spiffe://prod.lab/ns/e2e/sa/w"+x)
	target := topologyTarget(t, olga, dora, "pyfc-ledger-"+x, "pg-ledger-dynamic", "dc/corp-prod/ledger")
	binding := "pyfc-" + x
	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		t.Fatalf("binding: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	b := phase(t, olga, binding, "ACTIVE")
	defer revoke(t, olga, dora, binding, b)

	check := func() ([]pyResult, []pyResult) {
		t.Helper()
		res := pyResults(t, "flowcheck", "--target", target)
		var un []pyResult
		for _, r := range res {
			if r.Status == "unreachable" {
				un = append(un, r)
			}
		}
		return res, un
	}
	// the binding is ACTIVE for the admin API, but the workload API may still answer without it for a moment
	var res, un []pyResult
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
		if res, un = check(); len(res) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the workload API gives no flows for an ACTIVE binding after 30s")
		}
	}

	// FC-L1: every flow of the binding is reachable, TLS verified against the lab CA
	if len(un) != 0 {
		t.Fatalf("all flows reachable: %s", describePy(res))
	}
	var blocked pyResult
	for _, r := range res {
		if r.Binding != binding || r.Target != target {
			t.Errorf("a result of another binding: %+v", r)
		}
		if r.Status == "reachable" && blocked.Destination == "" && r.Port == 5432 {
			blocked = r // the target's database
		}
	}
	if blocked.Destination == "" {
		t.Fatalf("no reachable flow to the database (port 5432): %s", describePy(res))
	}

	// FC-L2: a prohibit route to the database host, and only its flow is reported
	flowcheckStep(t, "block", blocked.Destination)
	res, un = check()
	if len(un) == 0 || len(un) == len(res) {
		t.Fatalf("with the route, %d of %d are unreachable: %s", len(un), len(res), describePy(res))
	}
	for _, r := range un {
		if r.Destination != blocked.Destination || r.Error == "" {
			t.Errorf("an unexpected unreachable result: %+v", r)
		}
	}

	// FC-L3: the route removed, everything is reachable again
	flowcheckStep(t, "unblock", blocked.Destination)
	if res, un = check(); len(un) != 0 {
		t.Errorf("after the route is gone: %s", describePy(res))
	}

	// FC-L4: the cloud metadata address is denied by default, and no packet goes out
	denied := pyResults(t, "denied")
	if len(denied) != 1 || denied[0].Status != "skipped" || !strings.Contains(denied[0].Reason, "denied") {
		t.Errorf("a denied network: %+v", denied)
	}
}
