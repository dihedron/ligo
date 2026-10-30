//go:build lab

package serve

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The e2e of ligo serve on ligo1, run by lab.sh serve test against the
// service, with the lifecycle checks between its two halves
// (.specs/ligo-test-environment.md, "The ligo service on ligo1").

func e2eEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: run the e2e with test/lab/lab.sh serve test", name)
	}
	return v
}

// admin is a client of the admin API: a SPIFFE principal with its minted
// SVID, or an LDAP user with Basic credentials; it accepts only ligo's core
// identity as the server.
type admin struct {
	t          *testing.T
	base       string
	client     *http.Client
	user, pass string
}

func newAdmin(t *testing.T, who string) *admin {
	t.Helper()
	dir := e2eEnv(t, "LIGO_E2E_DIR")
	bundle, err := os.ReadFile(filepath.Join(dir, "olga-bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		t.Fatal("the prod.lab bundle holds no certificate")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, // the server's SVID has a URI SAN, no name: VerifyPeerCertificate checks it
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, 0, len(raw))
			for _, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				certs = append(certs, c)
			}
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				inter.AddCert(c)
			}
			if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return err
			}
			if len(certs[0].URIs) != 1 || certs[0].URIs[0].String() != "spiffe://prod.lab/ns/sys/sa/ligo" {
				return errors.New("the server is not ligo's core identity")
			}
			return nil
		}}
	a := &admin{t: t, base: e2eEnv(t, "LIGO_E2E_ADMIN")}
	if who == "olivia" {
		a.user, a.pass = "olivia", e2eEnv(t, "LIGO_TEST_LDAP_OLIVIA_PASS")
	} else {
		pair, err := tls.LoadX509KeyPair(filepath.Join(dir, who+"-svid.pem"), filepath.Join(dir, who+"-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	a.client = &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	return a
}

// do sends body as JSON and decodes the answer into a map.
func (a *admin) do(method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.base+path, rd)
	if a.user != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// approveAll approves every side of the change request in a filed answer,
// one side at a time, and returns the request as it ends.
func approveAll(t *testing.T, dora *admin, filed map[string]any) map[string]any {
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
		code, body := dora.do("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve",
			map[string]any{"payloadSha256": cr["payloadSha256"], "side": awaiting[0], "comment": "e2e"})
		if code != http.StatusOK {
			t.Fatalf("approve %v: %d %v", awaiting[0], code, body)
		}
		cr = body["changeRequest"].(map[string]any)
	}
	if cr["status"] != "APPLIED" {
		t.Fatalf("change request %s: %v", cr["status"], cr)
	}
	return cr
}

// phase waits until the binding reaches want, failing on FAILED.
func phase(t *testing.T, a *admin, name, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		code, b := a.do("GET", "/v1/admin/bindings/"+name, nil)
		if want == "" && code == http.StatusNotFound {
			return nil
		}
		st, _ := b["status"].(map[string]any)
		switch {
		case code == http.StatusOK && st["phase"] == want:
			return b
		case code == http.StatusOK && st["phase"] == "FAILED":
			t.Fatalf("binding %s failed: %v", name, st)
		case time.Now().After(deadline):
			t.Fatalf("binding %s: %d %v, want %q", name, code, st, want)
		}
		time.Sleep(time.Second)
	}
}

func names(t *testing.T) (source, target, binding string) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	return "e2e-src-" + x, "e2e-ledger-" + x, "e2e-" + x
}

// TestServeE2EApply: olga registers a source, publishes a target on
// pg-ledger and binds them; dora approves each side over the API; the
// binding becomes ACTIVE; olivia, a viewer by LDAP, reads it.
func TestServeE2EApply(t *testing.T) {
	olga, dora, olivia := newAdmin(t, "olga"), newAdmin(t, "dora"), newAdmin(t, "olivia")
	source, target, binding := names(t)
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")

	code, filed := olga.do("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": source},
		"identity": map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/e2e/sa/w` + x + `$`,
			"sampleSpiffeIds": []string{"spiffe://prod.lab/ns/e2e/sa/w" + x}}, "visibility": map[string]string{"mode": "PRIVATE"}})
	if code != http.StatusAccepted {
		t.Fatalf("source: %d %v", code, filed)
	}
	approveAll(t, dora, filed)

	code, filed = olga.do("POST", "/v1/admin/targets", map[string]any{"kind": "Target",
		"metadata":     map[string]string{"name": target, "platform": "pg-ledger", "scope": "dc/corp-prod/ledger"},
		"definition":   map[string]string{"database": "ledger", "schema": "ledger"},
		"accessLevels": []any{map[string]any{"name": "read", "grants": map[string][]string{"roles": {"LEDGER_RO_ROLE"}}}},
		"networkFlows": []any{map[string]any{"name": "ledger", "purpose": "DATA", "protocol": "TCP", "destination": "pg.ligo.lab",
			"ports": []int{5432}, "tls": true, "serverName": "pg.ligo.lab"}},
		"visibility": map[string]string{"mode": "PRIVATE"}})
	if code != http.StatusAccepted {
		t.Fatalf("target: %d %v", code, filed)
	}
	if cr := approveAll(t, dora, filed); len(cr["sides"].([]any)) != 2 {
		t.Errorf("target sides: %v", cr["sides"])
	}

	code, filed = olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		t.Fatalf("binding: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	b := phase(t, olga, binding, "ACTIVE")
	if b["active"] == nil {
		t.Errorf("no active snapshot: %v", b)
	}

	code, flows := olga.do("GET", "/v1/admin/bindings/"+binding+"/flows", nil)
	fs, _ := flows["networkFlows"].([]any)
	if code != http.StatusOK || len(fs) < 2 || fmt.Sprint(fs[0].(map[string]any)["declaredBy"]) != "target:"+target {
		t.Errorf("flows: %d %v", code, flows)
	}
	if code, b := olivia.do("GET", "/v1/admin/bindings/"+binding, nil); code != http.StatusOK || b["status"].(map[string]any)["phase"] != "ACTIVE" {
		t.Errorf("olivia: %d %v", code, b)
	}
	if code, b := olivia.do("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": "x" + source},
		"identity":   map[string]any{"trustDomain": "prod.lab", "svidRegex": `^spiffe://prod\.lab/ns/e2e/sa/v` + x + `$`},
		"visibility": map[string]string{"mode": "PRIVATE"}}); code != http.StatusForbidden {
		t.Errorf("a viewer registers a source: %d %v", code, b)
	}
}

// TestServeE2ERestarted: after reload, stop and start, the binding is still
// ACTIVE; olga revokes it, dora approves, it is deleted; the audit chain
// verifies.
func TestServeE2ERestarted(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	_, _, binding := names(t)
	b := phase(t, olga, binding, "ACTIVE")
	revision := int64(b["metadata"].(map[string]any)["revision"].(float64))
	code, filed := olga.do("DELETE", fmt.Sprintf("/v1/admin/bindings/%s?expectedRevision=%d", binding, revision), nil)
	if code != http.StatusAccepted {
		t.Fatalf("revoke: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	phase(t, olga, binding, "")
	if code, v := olga.do("GET", "/v1/admin/audit/verify", nil); code != http.StatusOK || v["valid"] != true {
		t.Errorf("audit verify: %d %v", code, v)
	}
}
