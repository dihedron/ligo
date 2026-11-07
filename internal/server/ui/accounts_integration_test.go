//go:build integration

package ui

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/governance"
)

const accountAdmins = "cn=ligo-account-admins,ou=groups,dc=ligo,dc=lab"

// accountAdmin signs in a new user holding account_admin alone; such a user
// has no page but this one to take the CSRF token from.
func accountAdmin(t *testing.T, v *sessionEnv) *browser {
	t.Helper()
	return v.signedInAs(t, "k"+v.user, accountAdmins, "/ui/accounts")
}

func (v *sessionEnv) signedInAs(t *testing.T, user, group, page string) *browser {
	t.Helper()
	v.dir.passwords[user] = "right"
	v.dir.groups[user] = []string{group}
	t.Cleanup(func() {
		_, _ = v.owner.Exec(context.Background(), "delete from admin_sessions where username = $1", user)
	})
	b := v.browser(t)
	if resp := b.signInAs(user, "right"); resp.StatusCode >= 400 {
		t.Fatalf("%s's login: %d", user, resp.StatusCode)
	}
	_, body := b.do("GET", page, nil, "HX-Request", "")
	m := csrfMeta.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s on %s: no CSRF token in %s", user, page, body)
	}
	b.csrf = m[1]
	return b
}

// accountName is unique across runs, as a retired name is never reused.
func accountName() string {
	return "t" + strings.ReplaceAll(uuid.NewV7().String(), "-", "")[:24]
}

func withAccounts(v *sessionEnv) {
	v.s.Config.Governance.Accounts = &governance.Accounts{Scope: "cloud/{account}", SourceScope: "cloud/{account}/app/{project}",
		TargetScope: "cloud/{account}/data/{tenancy}"}
}

// logBuffer takes a server's log lines while the test reads them.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// TestAccountsPage: an account_admin registers and retires through the page,
// whose refusals land in the form and whose link is shown (spec §7.4).
func TestAccountsPage(t *testing.T) {
	v := sessionSetup(t)
	withAccounts(v)
	k := accountAdmin(t, v)
	name := accountName()

	resp, body := k.do("GET", "/ui/accounts", nil, "HX-Request", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `href="/ui/accounts" aria-current="page"`) || !strings.Contains(body, `hx-post="/ui/accounts"`) {
		t.Fatalf("the list: %d %s", resp.StatusCode, body)
	}

	resp, _ = k.do("POST", "/ui/accounts", url.Values{"name": {name}, "displayName": {"Acme <b>Corp</b>"}})
	if resp.StatusCode != 200 || resp.Header.Get("HX-Redirect") != "/ui/accounts/"+name {
		t.Fatalf("register: %d %v", resp.StatusCode, resp.Header)
	}
	_, body = k.do("GET", "/ui/accounts", nil, "HX-Request", "")
	if !strings.Contains(body, `href="/ui/accounts/`+name+`"`) || !strings.Contains(body, "Acme &lt;b&gt;Corp&lt;/b&gt;") {
		t.Errorf("the list lacks the account, escaped: %s", body)
	}

	for what, form := range map[string]struct {
		name string
		code int
		text string
	}{"twice": {name, 409, "never reused"}, "a hyphen": {"a-b", 422, "lower case"}, "too long": {strings.Repeat("a", 31), 422, "at most 30"}} {
		resp, body := k.do("POST", "/ui/accounts", url.Values{"name": {form.name}})
		if resp.StatusCode != form.code || !strings.Contains(body, form.text) || resp.Header.Get("HX-Retarget") != "" {
			t.Errorf("%s: %d %v %s", what, resp.StatusCode, resp.Header, body)
		}
	}

	resp, body = k.do("GET", "/ui/accounts/"+name, nil, "HX-Request", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `hx-post="/ui/accounts/`+name+`/retire"`) || !strings.Contains(body, "hx-confirm=") {
		t.Fatalf("the account: %d %s", resp.StatusCode, body)
	}
	if resp, _ := k.do("GET", "/ui/accounts/nosuch", nil, "HX-Request", ""); resp.StatusCode != 404 {
		t.Errorf("no such account: %d", resp.StatusCode)
	}

	// in use: the trigger refuses, and the form shows why
	src := uuid.NewV7()
	if _, err := v.owner.Exec(context.Background(), `insert into sources (id, name, scope, account, trust_domain, svid_regex, visibility, created_by, updated_by)
		values ($1, $2, $3, $4, 'prod.internal', $5, 'PRIVATE', 't', 't')`, src, "src-"+name, "cloud/"+name+"/app/p", name, `^spiffe://prod\.internal/ns/`+name+`/sa/x$`); err != nil {
		t.Fatal(err)
	}
	if resp, body := k.do("GET", "/ui/accounts/"+name, nil, "HX-Request", ""); resp.StatusCode != 200 || !strings.Contains(body, "<dt>Sources</dt><dd>1</dd>") {
		t.Errorf("the counts: %s", body)
	}
	resp, body = k.do("POST", "/ui/accounts/"+name+"/retire", url.Values{})
	if resp.StatusCode != 409 || resp.Header.Get("HX-Retarget") != "" {
		t.Errorf("retire in use: %d %s", resp.StatusCode, body)
	}
	if _, err := v.owner.Exec(context.Background(), "update sources set state = 'RETIRED' where id = $1", src); err != nil {
		t.Fatal(err)
	}

	resp, _ = k.do("POST", "/ui/accounts/"+name+"/retire", url.Values{})
	if resp.StatusCode != 200 || resp.Header.Get("HX-Redirect") != "/ui/accounts/"+name {
		t.Fatalf("retire: %d %v", resp.StatusCode, resp.Header)
	}
	_, body = k.do("GET", "/ui/accounts/"+name, nil, "HX-Request", "")
	if strings.Contains(body, "/retire") || !strings.Contains(body, "RETIRED") {
		t.Errorf("a retired account still offers retiring: %s", body)
	}
	if resp, _ := k.do("POST", "/ui/accounts/"+name+"/retire", url.Values{}); resp.StatusCode != 409 {
		t.Errorf("retire twice: %d", resp.StatusCode)
	}
}

// TestAccountsPageRoles is TN-17 on the web UI: changing the registry takes
// account_admin; reading takes a role on the account; account_admin alone
// reaches nothing else, and is told where to go.
func TestAccountsPageRoles(t *testing.T) {
	v := sessionSetup(t)
	withAccounts(v)
	k := accountAdmin(t, v)
	name := accountName()
	if resp, _ := k.do("POST", "/ui/accounts", url.Values{"name": {name}}); resp.StatusCode != 200 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	full := v.signedInAs(t, "f"+v.user, "cn=ligo-full,ou=groups,dc=ligo,dc=lab", "/ui/bindings")
	if _, body := full.do("GET", "/ui/accounts/"+name, nil, "HX-Request", ""); !strings.Contains(body, "/retire") {
		t.Errorf("admin.full_access includes account_admin: %s", body)
	}

	viewer := v.signedInAs(t, "w"+v.user, viewers, "/ui/bindings")
	approver := v.signedInAs(t, "p"+v.user, approvers, "/ui/bindings")
	glassUser := v.signedInAs(t, "h"+v.user, glass, "/ui/break-glass/new-form")

	var logs logBuffer
	v.s.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	for who, b := range map[string]*browser{"viewer": viewer, "approver": approver, "break_glass": glassUser} {
		if resp, _ := b.do("POST", "/ui/accounts", url.Values{"name": {accountName()}}); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s registers: %d", who, resp.StatusCode)
		}
		if resp, _ := b.do("POST", "/ui/accounts/"+name+"/retire", url.Values{}); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s retires: %d", who, resp.StatusCode)
		}
	}

	for _, want := range []string{`msg="ui: request refused"`, "user=w" + v.user, "method=POST", "path=/ui/accounts/" + name + "/retire", "status=403", "request_id="} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("no %s in the log of the refusals: %s", want, logs.String())
		}
	}

	// a viewer on * sees the account, and no way to change it
	resp, body := viewer.do("GET", "/ui/accounts", nil, "HX-Request", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `href="/ui/accounts"`) || strings.Contains(body, `hx-post="/ui/accounts"`) {
		t.Errorf("a viewer's list: %d %s", resp.StatusCode, body)
	}
	resp, body = viewer.do("GET", "/ui/accounts/"+name, nil, "HX-Request", "")
	if resp.StatusCode != 200 || strings.Contains(body, "/retire") {
		t.Errorf("a viewer's account: %d %s", resp.StatusCode, body)
	}

	// an approver on dc/* has no role on it: the account stays hidden
	_, body = approver.do("GET", "/ui/accounts?after="+name[:len(name)-1], nil, "HX-Request", "")
	if strings.Contains(body, name) {
		t.Errorf("an approver on dc/* lists %s: %s", name, body)
	}
	if resp, _ := approver.do("GET", "/ui/accounts/"+name, nil, "HX-Request", ""); resp.StatusCode != 404 {
		t.Errorf("an approver on dc/* reads %s: %d", name, resp.StatusCode)
	}

	// break_glass alone reads no resources, and no accounts
	if resp, _ := glassUser.do("GET", "/ui/accounts", nil, "HX-Request", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("break_glass reads the list: %d", resp.StatusCode)
	}
	if _, body := glassUser.do("GET", "/ui/break-glass/new-form", nil, "HX-Request", ""); strings.Contains(body, `href="/ui/accounts"`) {
		t.Errorf("break_glass is shown the link: %s", body)
	}

	// account_admin alone: told where to go from the landing page, and no resources
	resp, body = k.do("GET", "/ui/bindings", nil, "HX-Request", "")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, `href="/ui/accounts"`) || !strings.Contains(body, "Accounts") {
		t.Errorf("account_admin's landing page: %d %s", resp.StatusCode, body)
	}
	if resp, _ := k.do("GET", "/ui/sources", nil, "HX-Request", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("account_admin reads sources: %d", resp.StatusCode)
	}

	// no accounts configured: no link
	v.s.Config.Governance.Accounts = nil
	if _, body := viewer.do("GET", "/ui/bindings", nil, "HX-Request", ""); strings.Contains(body, `href="/ui/accounts"`) {
		t.Errorf("a link with no governance.accounts: %s", body)
	}
}

// TestAccountsMaintenance: the forms are disabled, and the server refuses
// anyway.
func TestAccountsMaintenance(t *testing.T) {
	v := sessionSetup(t)
	withAccounts(v)
	k := accountAdmin(t, v)
	name := accountName()
	if resp, _ := k.do("POST", "/ui/accounts", url.Values{"name": {name}}); resp.StatusCode != 200 {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = v.owner.Exec(ctx, "update system_settings set maintenance_mode = false, maintenance_reason = null")
	})
	if _, err := v.owner.Exec(ctx, "update system_settings set maintenance_mode = true, maintenance_reason = 'x'"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/ui/accounts", "/ui/accounts/" + name} {
		if _, body := k.do("GET", path, nil, "HX-Request", ""); !strings.Contains(body, "disabled") {
			t.Errorf("%s: the form is not disabled: %s", path, body)
		}
	}
	if resp, _ := k.do("POST", "/ui/accounts", url.Values{"name": {accountName()}}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("register: %d", resp.StatusCode)
	}
	if resp, _ := k.do("POST", "/ui/accounts/"+name+"/retire", url.Values{}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("retire: %d", resp.StatusCode)
	}
}
