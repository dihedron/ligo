//go:build lab

package serve

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/ligo/pkg/adminclient"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// The e2e of pkg/adminclient against ligo (.specs/ligo-adminclient.md,
// chunk 6): an operator by SVID and a viewer by LDAP Basic credentials go
// through the package; the approver, a person, goes through the raw admin
// helper, since the package cannot decide (T-A4).

// acFileSource is the SVID minted for who, and the prod.lab bundle, as an
// adminclient.X509Source.
type acFileSource struct {
	*x509svid.SVID
	*x509bundle.Bundle
}

func acSource(t *testing.T, who string) acFileSource {
	t.Helper()
	dir := e2eEnv(t, "LIGO_E2E_DIR")
	svid, err := x509svid.Load(filepath.Join(dir, who+"-svid.pem"), filepath.Join(dir, who+"-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("prod.lab"), filepath.Join(dir, who+"-bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return acFileSource{svid, bundle}
}

func (s acFileSource) GetX509SVID() (*x509svid.SVID, error) { return s.SVID, nil }

func (s acFileSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.Bundle.GetX509BundleForTrustDomain(td)
}

const acLigoID = "spiffe://prod.lab/ns/sys/sa/ligo"

func acClient(t *testing.T, who, server string) *adminclient.Client {
	t.Helper()
	src := acSource(t, who)
	c, err := adminclient.New(adminclient.Config{ServerURL: server, X509Source: src, ServerID: acLigoID, Bundles: src, UserAgent: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// decide approves every side of cr as dora, a person, and returns when the
// request is no longer waiting for her.
func acApprove(t *testing.T, dora *admin, cr adminclient.ChangeRequest) {
	t.Helper()
	for _, side := range cr.AwaitingApproval {
		code, body := dora.do("POST", "/v1/admin/change-requests/"+cr.Id.String()+"/approve",
			map[string]any{"payloadSha256": cr.PayloadSha256, "side": side, "comment": "e2e"})
		if code != http.StatusOK {
			t.Fatalf("approve %s: %d %v", side, code, body)
		}
		if got, _ := body["changeRequest"].(map[string]any); got["status"] != "PENDING" {
			return // consent ANY: one side was enough
		}
	}
}

func acSpec[T any](t *testing.T, doc string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func acWait(t *testing.T, c *adminclient.Client, cr adminclient.ChangeRequest, o adminclient.WaitOptions) adminclient.ChangeRequest {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	o.Interval = time.Second
	cr, err := c.WaitChangeRequest(ctx, cr.Id.String(), o)
	if err != nil || !adminclient.IsApplied(cr) {
		t.Fatalf("change request %s: %s, %v", cr.Id, cr.Status, err)
	}
	return cr
}

// TestServeAdminClient: olga files a source, a target and a binding through
// the package, dora approves each, the package waits for them and for the
// binding to be ACTIVE and reads it back; a stale revision is ErrConflict; a
// viewer by LDAP reads and cannot file; a server that is not ligo's is
// refused.
func TestServeAdminClient(t *testing.T) {
	ctx := context.Background()
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	source, target, binding := "e2e-ac-src-"+x, "e2e-ac-ledger-"+x, "e2e-ac-"+x
	olga := acClient(t, "olga", e2eEnv(t, "LIGO_E2E_ADMIN"))
	dora := newAdmin(t, "dora")
	dora.base = e2eEnv(t, "LIGO_E2E_ADMIN2") // the other replica, as the apply test does

	cr, err := olga.CreateSource(ctx, acSpec[adminclient.SourceSpec](t, `{"kind":"Source","metadata":{"name":"`+source+`"},
		"identity":{"trustDomain":"prod.lab","svidRegex":"^spiffe://prod\\.lab/ns/e2e/sa/w`+x+`$","sampleSpiffeIds":["spiffe://prod.lab/ns/e2e/sa/w`+x+`"]},
		"visibility":{"mode":"PRIVATE"}}`), adminclient.Options{})
	if err != nil || cr.Status != adminclient.ChangeRequestStatus("PENDING") {
		t.Fatalf("CreateSource: %s, %v", cr.Status, err)
	}
	acApprove(t, dora, cr)
	acWait(t, olga, cr, adminclient.WaitOptions{})

	cr, err = olga.CreateTarget(ctx, acSpec[adminclient.TargetSpec](t, `{"kind":"Target","metadata":{"name":"`+target+`","platform":"pg-ledger","jurisdiction":"dc/corp-prod/ledger"},
		"definition":{"database":"ledger","schema":"ledger"},
		"accessLevels":[{"name":"read","grants":{"roles":["LEDGER_RO_ROLE"]}}],
		"networkFlows":[{"name":"ledger","purpose":"DATA","protocol":"TCP","destination":"pg.ligo.lab","ports":[5432],"tls":true,"serverName":"pg.ligo.lab"}],
		"visibility":{"mode":"PRIVATE"}}`), adminclient.Options{})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	acApprove(t, dora, cr)
	acWait(t, olga, cr, adminclient.WaitOptions{})

	cr, err = olga.CreateBinding(ctx, adminclient.BindingSpec{Name: binding, Source: source, Target: target, AccessLevel: "read"}, false, adminclient.Options{})
	if err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	acApprove(t, dora, cr)
	acWait(t, olga, cr, adminclient.WaitOptions{UntilBindingActive: true})

	b, err := olga.GetBinding(ctx, binding)
	if err != nil || b.Status.Phase != "ACTIVE" || len(b.Stages) == 0 {
		t.Fatalf("GetBinding: %+v, %v", b.Status, err)
	}
	if flows, err := olga.GetBindingFlows(ctx, binding); err != nil || len(flows) < 2 {
		t.Errorf("GetBindingFlows: %d flows, %v", len(flows), err)
	}
	var seen bool
	for it, err := range olga.ListTargetBindings(ctx, target, 1) {
		if err != nil {
			t.Fatal(err)
		}
		seen = seen || it.Metadata.Name == binding
	}
	if !seen {
		t.Error("ListTargetBindings does not list the binding")
	}

	// a stale revision is ErrConflict, and nothing is filed
	src, err := olga.GetSource(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	rev := src.Metadata.Revision
	upd := acSpec[adminclient.SourceSpec](t, `{"kind":"Source","metadata":{"name":"`+source+`"},
		"identity":{"trustDomain":"prod.lab","svidRegex":"^spiffe://prod\\.lab/ns/e2e/sa/w`+x+`$","sampleSpiffeIds":["spiffe://prod.lab/ns/e2e/sa/w`+x+`"]},
		"description":"updated","visibility":{"mode":"PRIVATE"}}`)
	if _, err := olga.UpdateSource(ctx, source, upd, rev+5, adminclient.Options{}); !errors.Is(err, adminclient.ErrConflict) {
		t.Errorf("a stale revision: %v", err)
	}

	// a viewer by LDAP Basic reads, and cannot file
	olivia, err := adminclient.New(adminclient.Config{ServerURL: e2eEnv(t, "LIGO_E2E_ADMIN"), ServerID: acLigoID, Bundles: acSource(t, "olga"),
		Basic: &adminclient.BasicAuth{Username: "olivia", Password: adminclient.Secret(e2eEnv(t, "LIGO_TEST_LDAP_OLIVIA_PASS"))}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = olivia.Close() }()
	if b, err := olivia.GetBinding(ctx, binding); err != nil || b.Status.Phase != "ACTIVE" {
		t.Errorf("olivia reads: %v", err)
	}
	if _, err := olivia.CreateSource(ctx, upd, adminclient.Options{}); !errors.Is(err, adminclient.ErrForbidden) {
		t.Errorf("a viewer files: %v", err)
	}

	// a server that is not ligo's core identity is refused, before any credential is sent
	wrong, err := adminclient.New(adminclient.Config{ServerURL: e2eEnv(t, "LIGO_E2E_ADMIN"), ServerID: "spiffe://prod.lab/ns/sys/sa/other", Bundles: acSource(t, "olga"),
		X509Source: acSource(t, "olga")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wrong.Close() }()
	if _, err := wrong.GetBinding(ctx, binding); err == nil {
		t.Error("a server with another SPIFFE ID was accepted")
	}

	// the binding is deleted through the package, for the next suites
	b, _ = olga.GetBinding(ctx, binding)
	del, err := olga.DeleteBinding(ctx, binding, b.Metadata.Revision, adminclient.Options{})
	if err != nil {
		t.Fatalf("DeleteBinding: %v", err)
	}
	acApprove(t, dora, del)
	acWait(t, olga, del, adminclient.WaitOptions{})
	if _, err := olga.GetBinding(ctx, binding); err == nil {
		t.Log("the binding is still readable while it is deleted") // the deletion settles asynchronously
	}
}

// TestServeAdminClientWait: a change request is filed on ligo1 and waited
// for there while lab.sh restarts ligo1; dora approves, through ligo2, once
// it is back; the wait ends APPLIED, having ridden out the restart.
func TestServeAdminClientWait(t *testing.T) {
	ctx := context.Background()
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	name := "e2e-ac-wait-" + x
	olga := acClient(t, "olga", e2eEnv(t, "LIGO_E2E_ADMIN"))
	dora := newAdmin(t, "dora")
	dora.base = e2eEnv(t, "LIGO_E2E_ADMIN2")

	cr, err := olga.CreateSource(ctx, acSpec[adminclient.SourceSpec](t, `{"kind":"Source","metadata":{"name":"`+name+`"},
		"identity":{"trustDomain":"prod.lab","svidRegex":"^spiffe://prod\\.lab/ns/e2e/sa/w`+x+`$","sampleSpiffeIds":["spiffe://prod.lab/ns/e2e/sa/w`+x+`"]},
		"visibility":{"mode":"PRIVATE"}}`), adminclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var got adminclient.ChangeRequest
	var waitErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		wctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		got, waitErr = olga.WaitChangeRequest(wctx, cr.Id.String(), adminclient.WaitOptions{Interval: time.Second, MaxInterval: 5 * time.Second})
	}()
	// lab.sh restarts ligo1 now: it stops the service about 3 s after this test starts, and starts it again
	if err := os.WriteFile(filepath.Join(e2eEnv(t, "LIGO_E2E_DIR"), "wait-filed"), []byte(cr.Id.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for { // lab.sh writes wait-restarted when ligo1 is back
		if _, err := os.Stat(filepath.Join(e2eEnv(t, "LIGO_E2E_DIR"), "wait-restarted")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ligo1 was not restarted")
		}
		time.Sleep(time.Second)
	}
	acApprove(t, dora, cr)
	wg.Wait()
	if waitErr != nil || !adminclient.IsApplied(got) {
		t.Fatalf("the wait across the restart: %s, %v", got.Status, waitErr)
	}
	if strings.TrimSpace(string(got.Id.String())) == "" {
		t.Error("no change request")
	}
}
