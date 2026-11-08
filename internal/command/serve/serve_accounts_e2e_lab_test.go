//go:build lab

package serve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The accounts' e2e, run by lab.sh serve test-accounts, on a server.yaml with
// governance.accounts and the platform pg-shared (.specs/ligo-tenancy.md §11).

// accountTarget files a public target of a tenancy on pg-shared, offering role
// at the level read.
func accountTarget(who *admin, name, jurisdiction, schema, role string) (int, map[string]any) {
	return who.do("POST", "/v1/admin/targets", map[string]any{"kind": "Target",
		"metadata":     map[string]string{"name": name, "platform": "pg-shared", "jurisdiction": jurisdiction},
		"definition":   map[string]string{"database": "ledger", "schema": schema},
		"accessLevels": []any{map[string]any{"name": "read", "grants": map[string][]string{"roles": {role}}}},
		"networkFlows": []any{map[string]any{"name": "ledger", "purpose": "DATA", "protocol": "TCP", "destination": "pg.ligo.lab",
			"ports": []int{5432}, "tls": true, "serverName": "pg.ligo.lab"}},
		"visibility": map[string]string{"mode": "PUBLIC"}})
}

func accountSource(who *admin, name, id string) (int, map[string]any) {
	return who.do("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": name},
		"identity":   map[string]any{"trustDomain": "prod.lab", "svidRegex": "^" + strings.ReplaceAll(id, ".", `\.`) + "$", "sampleSpiffeIds": []string{id}},
		"visibility": map[string]string{"mode": "PUBLIC"}})
}

// tryDecide approves one side as who, and returns the status.
func tryDecide(who *admin, filed map[string]any, side string) int {
	cr := filed["changeRequest"].(map[string]any)
	code, _ := who.do("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve",
		map[string]any{"payloadSha256": cr["payloadSha256"], "side": side, "comment": "e2e"})
	return code
}

// reloaded is the request as it stands, for decide to continue from.
func reloaded(t *testing.T, ada *admin, filed map[string]any) map[string]any {
	t.Helper()
	code, cr := ada.do("GET", "/v1/admin/change-requests/"+filed["changeRequest"].(map[string]any)["id"].(string), nil)
	if code != http.StatusOK {
		t.Fatalf("the change request: %d %v", code, cr)
	}
	if inner, ok := cr["changeRequest"].(map[string]any); ok {
		cr = inner
	}
	return map[string]any{"changeRequest": cr}
}

func filedOK(t *testing.T, what string, code int, filed map[string]any) {
	t.Helper()
	if code != http.StatusAccepted {
		t.Fatalf("%s: %d %v", what, code, filed)
	}
}

// selectFrom reads a tenancy's table with a credential; err is PostgreSQL's.
func selectFrom(t *testing.T, user, password, schema string) error {
	t.Helper()
	conn, err := ledgerConn(t, user, password)
	if err != nil {
		t.Fatalf("the credential does not connect: %v", err)
	}
	ctx := context.Background()
	defer func() { _ = conn.Close(ctx) }()
	var n int
	return conn.QueryRow(ctx, "SELECT count(*) FROM "+schema+".entries").Scan(&n)
}

// TestServeAccounts: two accounts on one PostgreSQL, from their registration
// to a workload that reads its own schema and no other.
func TestServeAccounts(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	ada, peter := newAdmin(t, "ada"), newAdmin(t, "peter")
	amy, alan, anne, pat := newAdmin(t, "amy"), newAdmin(t, "alan"), newAdmin(t, "anne"), newAdmin(t, "pat")
	gus, gail := newAdmin(t, "gus"), newAdmin(t, "gail")
	id := "spiffe://prod.lab/acct/acme/project/app01/sa/w" + x

	// TN-4: nothing is usable before its account is registered
	if code, b := accountSource(ada, "acme-early-"+x, id); code != http.StatusUnprocessableEntity || !strings.Contains(fmt.Sprint(b["type"]), "account-not-registered") {
		t.Fatalf("TN-4: %d %v", code, b)
	}
	for _, name := range []string{"acme", "globex"} {
		if code, b := ada.do("POST", "/v1/admin/accounts", map[string]any{"name": name}); code != http.StatusCreated {
			t.Fatalf("register %s: %d %v", name, code, b)
		}
	}

	// TN-7: the directory's groups give roles on the account alone
	code, list := alan.do("GET", "/v1/admin/accounts", nil)
	if names := fmt.Sprint(list["items"]); code != http.StatusOK || !strings.Contains(names, "acme") || strings.Contains(names, "globex") {
		t.Errorf("TN-7: alan's accounts: %d %v", code, list)
	}
	if code, _ := alan.do("GET", "/v1/admin/accounts/globex", nil); code != http.StatusNotFound {
		t.Errorf("TN-7: alan reads globex: %d", code)
	}

	// TN-18: pat approves in project app01 alone
	source := "acme-src-" + x
	code, filed := accountSource(amy, source, id)
	filedOK(t, "source", code, filed)
	other := "acme-other-" + x
	code, otherFiled := accountSource(amy, other, "spiffe://prod.lab/acct/acme/project/app02/sa/w"+x)
	filedOK(t, "app02's source", code, otherFiled)
	if code := tryDecide(pat, otherFiled, "OWNER"); code != http.StatusNotFound { // no role there: not even shown
		t.Errorf("TN-18: pat decides in app02: %d", code)
	}
	if code := tryDecide(pat, filed, "OWNER"); code != http.StatusOK {
		t.Errorf("TN-18: pat decides in app01: %d", code)
	}
	decide(t, otherFiled, map[string]*admin{"OWNER": alan})

	// TN-1, TN-2: a target's schema and roles follow from its jurisdiction
	if code, b := accountTarget(amy, "acme-wrong-"+x, "tenants/acme/data/db01", "globex_db02", "globex_db02_read"); code != http.StatusUnprocessableEntity ||
		!strings.Contains(fmt.Sprint(b["type"]), "namespace-mismatch") {
		t.Errorf("TN-1: %d %v", code, b)
	}
	if code, b := accountTarget(amy, "acme-role-"+x, "tenants/acme/data/db01", "acme_db01", "globex_db02_read"); code/100 == 2 {
		t.Errorf("TN-2: another tenant's role: %d %v", code, b)
	}

	acmeTarget, globexTarget := "acme-db01-"+x, "globex-db02-"+x
	code, filed = accountTarget(amy, acmeTarget, "tenants/acme/data/db01", "acme_db01", "acme_db01_read")
	filedOK(t, "acme's target", code, filed)
	if code := tryDecide(pat, filed, "OWNER"); code != http.StatusNotFound {
		t.Errorf("TN-18: pat decides in data: %d", code)
	}
	decide(t, filed, map[string]*admin{"OWNER": alan, "PLATFORM": peter})
	code, filed = accountTarget(gus, globexTarget, "tenants/globex/data/db02", "globex_db02", "globex_db02_read")
	filedOK(t, "globex's target", code, filed)
	if code := tryDecide(alan, filed, "OWNER"); code != http.StatusNotFound {
		t.Errorf("TN-7: alan decides in globex: %d", code)
	}
	decide(t, filed, map[string]*admin{"OWNER": gail, "PLATFORM": peter})

	// TN-10: inside one account, two of its approvers
	inside := "acme-in-" + x
	code, filed = amy.do("POST", "/v1/admin/bindings", map[string]any{"name": inside, "source": source, "target": acmeTarget, "accessLevel": "read"})
	filedOK(t, "the binding inside", code, filed)
	if code := tryDecide(alan, filed, "SOURCE"); code != http.StatusOK {
		t.Fatalf("TN-10: alan on SOURCE: %d", code)
	}
	if code := tryDecide(alan, filed, "TARGET"); code == http.StatusOK {
		t.Error("TN-10: one person decided both sides")
	}
	decide(t, reloaded(t, ada, filed), map[string]*admin{"TARGET": anne})
	phase(t, ada, inside, "ACTIVE")
	user, password := storeCredential(t, acmeTarget)
	if err := selectFrom(t, user, password, "acme_db01"); err != nil {
		t.Errorf("the credential does not read its schema: %v", err)
	}
	if err := selectFrom(t, user, password, "globex_db02"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the credential reads another tenant's schema: %v", err)
	}

	// TN-11, TN-13, TN-12: across accounts, the platform's approver on TARGET
	across := "acme-globex-" + x
	code, filed = amy.do("POST", "/v1/admin/bindings", map[string]any{"name": across, "source": source, "target": globexTarget, "accessLevel": "read"})
	filedOK(t, "the binding across", code, filed)
	if code := tryDecide(peter, filed, "SOURCE"); code != http.StatusForbidden {
		t.Errorf("TN-13: the platform's approver on SOURCE: %d", code)
	}
	if code := tryDecide(alan, filed, "TARGET"); code != http.StatusForbidden {
		t.Errorf("TN-11: acme's approver on globex's TARGET: %d", code)
	}
	if code := tryDecide(alan, filed, "SOURCE"); code != http.StatusOK {
		t.Fatalf("alan on SOURCE: %d", code)
	}
	decide(t, reloaded(t, ada, filed), map[string]*admin{"TARGET": peter})
	phase(t, ada, across, "ACTIVE")
	code, trail := ada.do("GET", "/v1/admin/bindings/"+across+"/audit", nil)
	raw, _ := json.Marshal(trail)
	if code != http.StatusOK || !strings.Contains(string(raw), `"decidedAs":"PLATFORM"`) || !strings.Contains(string(raw), "BINDING_TARGET_DECIDED_BY_PLATFORM") {
		t.Errorf("TN-12: the trail: %d %s", code, raw)
	}
	user, password = storeCredential(t, globexTarget)
	if err := selectFrom(t, user, password, "globex_db02"); err != nil {
		t.Errorf("TN-12: the credential does not read globex's schema: %v", err)
	}

	// TN-15: registered on one replica, effective on the other
	ivan := newAdmin(t, "ivan")
	ivan.base = e2eEnv(t, "LIGO_E2E_ADMIN2")
	if code, _ := ivan.do("GET", "/v1/admin/accounts/initech", nil); code != http.StatusForbidden {
		t.Fatalf("TN-15: before the registration: %d", code)
	}
	if code, b := ada.do("POST", "/v1/admin/accounts", map[string]any{"name": "initech"}); code != http.StatusCreated {
		t.Fatalf("register initech: %d %v", code, b)
	}
	start := time.Now()
	for {
		code, _ := ivan.do("GET", "/v1/admin/accounts/initech", nil)
		if code == http.StatusOK {
			t.Logf("TN-15: effective on the other replica after %v", time.Since(start).Round(time.Millisecond))
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("TN-15: not effective on the other replica: %d", code)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
