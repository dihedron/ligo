package admin

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func manifest(t *testing.T, text string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

const pendingAnswer = `{"changeRequest":{"id":"c1","resourceType":"BINDING","resourceName":"b1","status":"PENDING","payloadSha256":"ff",
	"sides":[{"side":"TARGET","scope":"dc/x/ledger","basis":"HUMAN","decision":null},{"side":"SOURCE","scope":"dc/x","basis":"AUTO","decision":"APPROVED"}]},"resource":null}`

// TestReadManifest: YAML documents and JSON arrays, sorted Source, Target,
// Binding, without apiVersion, and without kind for bindings; errors name
// the document.
func TestReadManifest(t *testing.T) {
	docs, err := readManifest(manifest(t, `apiVersion: ligo.dihedron.org/v1alpha1
kind: Binding
name: b1
source: s1
target: t1
accessLevel: read
expiresAt: 2027-01-01T00:00:00Z
---
kind: Source
metadata: {name: s1}
---
[{"kind": "Target", "metadata": {"name": "t1"}, "expectedRevision": 2}]
`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range docs {
		got = append(got, d.kind+":"+d.name)
		if _, ok := d.body["apiVersion"]; ok {
			t.Errorf("%s keeps apiVersion", d.name)
		}
	}
	if strings.Join(got, ",") != "Source:s1,Target:t1,Binding:b1" || docs[2].body["kind"] != nil || docs[0].body["kind"] != "Source" ||
		!docs[0].creates() || docs[1].creates() {
		t.Errorf("documents: %v %+v", got, docs)
	}
	for text, want := range map[string]string{"kind: Pod\nname: x\n": "kind must be", "kind: Binding\n": "has no name", "- 1\n": "not an object",
		"apiVersion: v1\nkind: Source\nmetadata: {name: s}\n": "apiVersion", "kind: [": "manifest"} {
		if _, err := readManifest(manifest(t, text)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", text, err)
		}
	}
	if _, err := readManifest(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("a missing file")
	}
}

// TestApply: a new source named by one binding goes inline with it; the
// others are filed in order; pending sides print the approver's command;
// a second binding of a new source is refused before anything is filed.
func TestApply(t *testing.T) {
	f := newFake(t, map[string][]string{
		"/v1/admin/targets":  {`{"changeRequest":{"id":"c0","resourceType":"TARGET","resourceName":"t1","status":"APPLIED"},"resource":{"metadata":{"revision":1}}}`},
		"/v1/admin/bindings": {pendingAnswer},
	})
	var out bytes.Buffer
	file := manifest(t, `kind: Source
metadata: {name: s1}
---
kind: Target
metadata: {name: t1}
---
name: b1
kind: Binding
source: s1
target: t1
accessLevel: read
`)
	cmd := &Apply{Base: f.base(t, "table", &out), File: file, Wait: true, ApprovalRef: "CHG-1", AutomationContext: `{"pipeline":"p"}`}
	if err := cmd.Execute(nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.requests, ";") != "POST /v1/admin/targets;POST /v1/admin/bindings?wait=true" {
		t.Errorf("requests: %v", f.requests)
	}
	if b := f.bodies[1]; !strings.Contains(b, `"inlineSource":{"kind":"Source","metadata":{"name":"s1"}}`) || strings.Contains(b, `"kind":"Binding"`) ||
		!strings.Contains(b, `"approvalReference":"CHG-1"`) || !strings.Contains(b, `"automationContext":{"pipeline":"p"}`) {
		t.Errorf("binding body: %s", b)
	}
	for _, want := range []string{"applied t1: change request c0 APPLIED", "revision 1", "applied b1: change request c1 PENDING",
		`awaiting side TARGET (scope dc/x/ledger): ligo cr approve c1 --sha256 ff --side TARGET -m "<comment>"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "null") || strings.Contains(out.String(), "--side SOURCE") {
		t.Errorf("a decided side is listed:\n%s", out.String())
	}

	two := manifest(t, "kind: Source\nmetadata: {name: s1}\n---\n{kind: Binding, name: b1, source: s1}\n---\n{kind: Binding, name: b2, source: s1}\n")
	n := len(f.requests)
	if err := (&Apply{Base: f.base(t, "table", &out), File: two}).Execute(nil); err == nil || !strings.Contains(err.Error(), "named by 2 bindings") ||
		len(f.requests) != n {
		t.Errorf("two bindings of a new source: %v", err)
	}
	if err := (&Apply{Base: f.base(t, "table", &out), File: file, AutomationContext: "[1]"}).Execute(nil); err == nil {
		t.Error("an automation context that is not an object")
	}
}

// TestApplyExisting: a create refused because the resource exists names
// its current revision.
func TestApplyExisting(t *testing.T) {
	f := newFake(t, map[string][]string{"/v1/admin/sources/s1": {`{"metadata":{"name":"s1","revision":4}}`}})
	f.srv.Config.Handler = conflict(f)
	var out bytes.Buffer
	err := (&Apply{Base: f.base(t, "table", &out), File: manifest(t, "kind: Source\nmetadata: {name: s1}\n")}).Execute(nil)
	if err == nil || !strings.Contains(err.Error(), "source s1 exists at revision 4: add expectedRevision: 4") {
		t.Errorf("existing: %v", err)
	}
}

// TestWriteCommands: each command's method, path and body.
func TestWriteCommands(t *testing.T) {
	applied := `{"changeRequest":{"id":"c2","resourceType":"BINDING","resourceName":"b1","status":"APPLIED"},"resource":{"status":{"phase":"DELETING","workflowId":"w"}}}`
	f := newFake(t, map[string][]string{
		"/v1/admin/bindings/b1":                           {applied},
		"/v1/admin/sources/s1/retire":                     {applied},
		"/v1/admin/bindings/b1/retry":                     {`{"binding":{"metadata":{"name":"b1"},"status":{"phase":"PROVISIONING"}}}`},
		"/v1/admin/bindings/b1/rotate":                    {`{"binding":{"metadata":{"name":"b1"}}}`},
		"/v1/admin/sources/test":                          {`{"scope":"dc/x"}`},
		"/v1/admin/sources/s1/deprecate":                  {applied},
		"/v1/admin/targets/t1/reactivate":                 {applied},
		"/v1/admin/targets/t1/access-levels/write/retire": {applied},
		"/v1/admin/targets/t1/bindings/revoke":            {`{"changeRequests":[{"id":"c3","resourceName":"b1","status":"PENDING"}],"errors":[]}`},
		"/v1/admin/change-requests/c1/approve":            {applied},
		"/v1/admin/change-requests/c1/decline":            {applied},
		"/v1/admin/change-requests/c1/withdraw":           {applied},
		"/v1/admin/change-requests/c1/ratify":             {applied},
		"/v1/admin/change-requests/c1/revert":             {applied},
		"/v1/admin/maintenance":                           {`{"maintenanceMode":true,"inFlight":0}`},
		"/v1/admin/break-glass":                           {applied},
		"/v1/admin/governance/evaluate":                   {`{"resourceType":"BINDING","name":"b1","consent":"ALL","sides":[]}`},
	})
	var out bytes.Buffer
	b := f.base(t, "table", &out)
	waitDelete, waitPoll = 100*time.Millisecond, 20*time.Millisecond
	state := StateChange{Base: b, ExpectedRevision: 2, Args: NameArg{"s1"}}
	tstate := StateChange{Base: b, ExpectedRevision: 2, Args: NameArg{"t1"}}
	op := operation{Base: b}
	op.Args.Name = "b1"
	del := &Delete{Base: b, ExpectedRevision: 3, ApprovalRef: "CHG-2", Wait: true, Args: ResourceArgs{"binding", "b1"}}
	level := &TargetLevel{Base: b, ExpectedRevision: 5}
	level.Args.Action, level.Args.Target, level.Args.Level = "retire", "t1", "write"
	bgDel := &BreakGlassDelete{Base: b, BGOptions: BGOptions{Justification: "j", Incident: "INC1", TTL: "4h"}, ExpectedRevision: 3}
	bgDel.Args.Name = "b1"
	bgFile := manifest(t, "kind: Source\nmetadata: {name: s9}\n---\n{kind: Binding, name: b1, source: s9, target: t1, accessLevel: read}\n")
	for _, tc := range []struct {
		name          string
		run           func([]string) error
		request, body string
	}{
		{"delete binding", del.Execute, "DELETE /v1/admin/bindings/b1?expectedRevision=3", `"approvalReference":"CHG-2"`},
		{"delete source", (&Delete{Base: b, ExpectedRevision: 1, Args: ResourceArgs{"source", "s1"}}).Execute, "POST /v1/admin/sources/s1/retire", `"expectedRevision":1`},
		{"retry", (&Retry{op}).Execute, "POST /v1/admin/bindings/b1/retry", ""},
		{"rotate", (&Rotate{op}).Execute, "POST /v1/admin/bindings/b1/rotate", ""},
		{"source test", (&SourceTest{Base: b, TrustDomain: "prod.lab", Regex: "^x$", SpiffeIDs: []string{"spiffe://prod.lab/x"}, Current: "s1"}).Execute,
			"POST /v1/admin/sources/test", `"currentSource":"s1"`},
		{"source deprecate", (&SourceDeprecate{state}).Execute, "POST /v1/admin/sources/s1/deprecate", `{"expectedRevision":2}`},
		{"target reactivate", (&TargetReactivate{tstate}).Execute, "POST /v1/admin/targets/t1/reactivate", `{"expectedRevision":2}`},
		{"target level", level.Execute, "POST /v1/admin/targets/t1/access-levels/write/retire", `{"expectedRevision":5}`},
		{"revoke-bindings", (&TargetRevoke{Base: b, Source: "s1", Comment: "containment", Args: NameArg{"t1"}}).Execute,
			"POST /v1/admin/targets/t1/bindings/revoke", `"comment":"containment"`},
		{"approve", (&ChangeRequestApprove{Base: b, SHA256: "ff", Side: "TARGET", Args: crID{"c1"}}).Execute,
			"POST /v1/admin/change-requests/c1/approve", `"payloadSha256":"ff"`},
		{"decline", (&ChangeRequestDecline{Base: b, Comment: "no", Args: crID{"c1"}}).Execute, "POST /v1/admin/change-requests/c1/decline", `"comment":"no"`},
		{"withdraw", (&ChangeRequestWithdraw{Base: b, Args: crID{"c1"}}).Execute, "POST /v1/admin/change-requests/c1/withdraw", ""},
		{"ratify", (&ChangeRequestRatify{Base: b, Comment: "ok", Side: "SOURCE", Args: crID{"c1"}}).Execute, "POST /v1/admin/change-requests/c1/ratify", `"side":"SOURCE"`},
		{"revert", (&ChangeRequestRevert{Base: b, Args: crID{"c1"}}).Execute, "POST /v1/admin/change-requests/c1/revert", ""},
		{"maintenance on", (&MaintenanceOn{Base: b, Reason: "upgrade"}).Execute, "PUT /v1/admin/maintenance", `{"enabled":true,"reason":"upgrade"}`},
		{"maintenance off", (&MaintenanceOff{Base: b}).Execute, "PUT /v1/admin/maintenance", `{"enabled":false,"reason":""}`},
		{"break-glass apply", (&BreakGlassApply{Base: b, BGOptions: BGOptions{Justification: "j", Incident: "INC1"}, File: bgFile}).Execute,
			"POST /v1/admin/break-glass", `"inlineSource":{"kind":"Source","metadata":{"name":"s9"}}`},
		{"break-glass delete", bgDel.Execute, "POST /v1/admin/break-glass", `"operation":"DELETE"`},
		{"governance check", (&GovernanceCheck{Base: b, File: bgFile}).Execute, "POST /v1/admin/governance/evaluate", `"source":{"svidRegex":null,"trustDomain":null}`},
	} {
		out.Reset()
		if err := tc.run(nil); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		f.mu.Lock()
		got, body := f.requests[len(f.requests)-1], f.bodies[len(f.bodies)-1]
		f.mu.Unlock()
		if tc.name == "delete binding" { // then --wait asked for it until its deadline
			for i, r := range f.requests {
				if strings.HasPrefix(r, "DELETE ") {
					got, body = r, f.bodies[i]
				}
			}
		}
		if got != tc.request || !strings.Contains(body, tc.body) {
			t.Errorf("%s: %q %s", tc.name, got, body)
		}
	}
	if err := (&TargetRevoke{Base: b, Comment: "x", Args: NameArg{"t1"}}).Execute(nil); err == nil {
		t.Error("revoke-bindings without --source or --source-scope")
	}
	if err := (&BreakGlassApply{Base: b, File: manifest(t, "{kind: Target, metadata: {name: t}}\n")}).Execute(nil); err == nil {
		t.Error("break-glass apply of a target")
	}
}

// conflict answers 409 to POST /v1/admin/sources, and f's answers
// otherwise.
func conflict(f *fake) http.Handler {
	next := f.srv.Config.Handler
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/admin/sources" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"type":"urn:ligo:problem:invalid-transition","title":"Conflict","status":409,"detail":"metadata.name \"s1\" is in use"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
