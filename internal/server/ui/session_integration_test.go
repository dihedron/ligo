//go:build integration

package ui

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/adminauth"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/ratelimit"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// insecure: CI's container has no TLS; the lab's DSNs use verify-full.
var insecure = os.Getenv("CI") != ""

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

const viewers = "cn=ligo-viewers,ou=groups,dc=ligo,dc=lab"
const operators = "cn=ligo-operators-prod,ou=groups,dc=ligo,dc=lab"

// directory is a fake LDAP: users with a password and groups.
type directory struct {
	passwords map[string]string
	groups    map[string][]string
	down      bool
}

func (d *directory) Authenticate(_ context.Context, user, password string) (authz.Principal, error) {
	if p, ok := d.passwords[user]; !ok || p != password || password == "" {
		return authz.Principal{}, adminauth.ErrInvalidCredentials
	}
	return d.Lookup(context.Background(), user)
}

func (d *directory) Lookup(_ context.Context, user string) (authz.Principal, error) {
	if d.down {
		return authz.Principal{}, errors.New("directory down")
	}
	if _, ok := d.passwords[user]; !ok {
		return authz.Principal{}, adminauth.ErrInvalidCredentials
	}
	return authz.Principal{Name: user, Groups: slices.Clone(d.groups[user])}, nil
}

type sessionEnv struct {
	srv   *httptest.Server
	owner *pgxpool.Pool
	dir   *directory
	user  string
}

func sessionSetup(t *testing.T) *sessionEnv {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = migrate.Apply(ctx, conn, migrations.FS)
	_ = conn.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), insecure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	user := "u" + uuid.NewV7().String()[24:]
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), "DELETE FROM admin_sessions WHERE username = $1", user)
	})
	az, err := authz.New([]config.RoleBinding{{LDAPGroupDN: viewers, Role: config.RoleViewer, Scopes: []string{"*"}},
		{LDAPGroupDN: operators, Role: config.RoleOperator, Scopes: []string{"dc/corp-prod"}}})
	if err != nil {
		t.Fatal(err)
	}
	d := &directory{passwords: map[string]string{user: "right"}, groups: map[string][]string{user: {viewers}}}
	s := newServer(t)
	s.DB, s.LDAP, s.Authz, s.Logins = pools.App, d, az, &ratelimit.Logins{PerIPPerMin: 100, PerUserPerMin: 3}
	s.Listener = config.AdminListener{ExternalOrigin: "https://ligo.example", Session: config.Session{IdleTimeout: 30 * time.Minute,
		AbsoluteTimeout: 8 * time.Hour, AuthzRecheckInterval: 5 * time.Minute}}
	srv := httptest.NewTLSServer(s.Handler())
	t.Cleanup(srv.Close)
	return &sessionEnv{srv: srv, owner: owner, dir: d, user: user}
}

// browser is a client with a cookie jar, as the UI's pages would send.
type browser struct {
	t       *testing.T
	env     *sessionEnv
	client  *http.Client
	csrf    string
	headers map[string]string
}

func (v *sessionEnv) browser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, env: v, headers: map[string]string{"Sec-Fetch-Site": "same-origin", "HX-Request": "true"},
		client: &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}}}} //nolint:gosec // the test server's certificate
}

func (b *browser) do(method, path string, form url.Values, headers ...string) (*http.Response, string) {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, b.env.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	if b.csrf != "" {
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i+1] == "" {
			req.Header.Del(headers[i])
		} else {
			req.Header.Set(headers[i], headers[i+1])
		}
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

func cookieOf(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

var (
	preloginField = regexp.MustCompile(`name="prelogin" value="([0-9a-f]{64})"`)
	csrfMeta      = regexp.MustCompile(`<meta name="csrf-token" content="([0-9a-f]{64})">`)
)

// signIn loads the login page and posts the credentials.
func (b *browser) signIn(password string) *http.Response {
	b.t.Helper()
	_, page := b.do("GET", "/ui/login", nil)
	m := preloginField.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatalf("no pre-login field: %s", page)
	}
	resp, _ := b.do("POST", "/ui/login", url.Values{"prelogin": {m[1]}, "username": {b.env.user}, "password": {password}})
	return resp
}

// page loads /ui/bindings and keeps its CSRF token.
func (b *browser) page() (*http.Response, string) {
	b.t.Helper()
	resp, body := b.do("GET", "/ui/bindings", nil, "HX-Request", "")
	if m := csrfMeta.FindStringSubmatch(body); m != nil {
		b.csrf = m[1]
	}
	return resp, body
}

func (v *sessionEnv) audits(t *testing.T, action string) int {
	var n int
	if err := v.owner.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1 AND snapshot->>'username' = $2`,
		action, v.user).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestLogin: the pre-login double-submit (§7.3 rule 1), refused and
// limited logins (rule 6), then a session whose token only the cookie holds
// (rule 2).
func TestLogin(t *testing.T) {
	v := sessionSetup(t)
	b := v.browser(t)
	resp, page := b.do("GET", "/ui/login", nil)
	pre := cookieOf(resp, preloginCookie)
	if resp.StatusCode != 200 || pre == nil || !pre.Secure || !pre.HttpOnly || pre.SameSite != http.SameSiteStrictMode || pre.Path != "/" ||
		pre.Domain != "" || !strings.Contains(page, `value="`+pre.Value+`"`) {
		t.Fatalf("login page: %d %+v", resp.StatusCode, pre)
	}
	for name, form := range map[string]url.Values{
		"no pre-login field": {"username": {v.user}, "password": {"right"}},
		"another value":      {"prelogin": {strings.Repeat("0", 64)}, "username": {v.user}, "password": {"right"}},
	} {
		if resp, _ := b.do("POST", "/ui/login", form); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	if resp, _ := b.do("POST", "/ui/login", url.Values{"prelogin": {pre.Value}, "username": {v.user}, "password": {"right"}},
		"Sec-Fetch-Site", "cross-site", "Origin", "https://evil.example"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site login: %d", resp.StatusCode)
	}
	if resp := b.signIn("wrong"); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("HX-Retarget") != "#page-errors" {
		t.Errorf("wrong password: %d %v", resp.StatusCode, resp.Header)
	}
	if v.audits(t, "SESSION_LOGIN_FAILED") != 1 {
		t.Error("the failed login is not audited")
	}
	resp = b.signIn("right")
	sess := cookieOf(resp, sessionCookie)
	if resp.StatusCode != 200 || resp.Header.Get("HX-Redirect") != "/ui/bindings" || sess == nil || !sess.Secure || !sess.HttpOnly ||
		sess.SameSite != http.SameSiteStrictMode || sess.Domain != "" || len(sess.Value) != 64 {
		t.Fatalf("login: %d %v %+v", resp.StatusCode, resp.Header, sess)
	}
	if c := cookieOf(resp, preloginCookie); c == nil || c.MaxAge >= 0 {
		t.Errorf("the pre-login cookie is not cleared: %+v", c)
	}
	var stored, csrf string
	if err := v.owner.QueryRow(context.Background(), `SELECT token_sha256, csrf_token FROM admin_sessions WHERE username = $1`, v.user).
		Scan(&stored, &csrf); err != nil || stored != hash(sess.Value) || stored == sess.Value || len(csrf) != 64 {
		t.Errorf("stored session: %q %q %v", stored, csrf, err)
	}
	if resp, body := b.page(); resp.StatusCode != 200 || b.csrf != csrf || !strings.Contains(body, "Signed in as "+v.user) {
		t.Errorf("signed-in page: %d %s", resp.StatusCode, body)
	}
	if v.audits(t, "SESSION_LOGIN") != 1 {
		t.Error("the login is not audited")
	}

	// three refused logins (login_per_user_per_min 3) lock the user out, the right password included
	other := v.browser(t)
	for range 2 {
		other.signIn("wrong")
	}
	if resp := other.signIn("right"); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("after 3 failures: %d", resp.StatusCode)
	}
	v.dir.groups[v.user] = nil
	if resp := v.browser(t).signIn("right"); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("still limited: %d", resp.StatusCode)
	}
}

// TestSessionCSRF: actions need the session's CSRF token and the UI's own
// origin (§7.3 rule 4); the theme preference sets its cookie.
func TestSessionCSRF(t *testing.T) {
	v := sessionSetup(t)
	b := v.browser(t)
	b.signIn("right")
	b.page()
	form := url.Values{"mode": {"dark"}}
	for name, h := range map[string][]string{
		"no CSRF token":      {"X-CSRF-Token", ""},
		"another CSRF token": {"X-CSRF-Token", strings.Repeat("a", 64)},
		"cross-site":         {"Sec-Fetch-Site", "cross-site"},
	} {
		if resp, _ := b.do("POST", "/ui/preferences/theme", form, h...); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	if resp, _ := b.do("POST", "/ui/preferences/theme", form, "Sec-Fetch-Site", "", "Origin", "https://ligo.example"); resp.StatusCode != 200 {
		t.Errorf("the configured origin: %d", resp.StatusCode)
	}
	resp, _ := b.do("POST", "/ui/preferences/theme", form)
	c := cookieOf(resp, themeCookie)
	if resp.StatusCode != 200 || resp.Header.Get("HX-Refresh") != "true" || c == nil || c.Value != "dark" || !c.HttpOnly || !c.Secure {
		t.Errorf("theme: %d %v %+v", resp.StatusCode, resp.Header, c)
	}
	if _, body := b.page(); !strings.Contains(body, `data-theme="dark"`) {
		t.Error("the chosen mode is not rendered")
	}
	if resp, _ := b.do("POST", "/ui/preferences/theme", url.Values{"mode": {"sepia"}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("unknown mode: %d", resp.StatusCode)
	}
}

// TestSessionLifetime: idle and absolute timeouts, the roles re-check
// with token rotation, AC-17 and logout (§7.3 rules 3 and 5).
func TestSessionLifetime(t *testing.T) {
	v := sessionSetup(t)
	ctx := context.Background()
	shift := func(column, by string) {
		t.Helper()
		if _, err := v.owner.Exec(ctx, "UPDATE admin_sessions SET "+column+" = "+column+" - interval '"+by+"' WHERE username = $1 AND revoked_at IS NULL",
			v.user); err != nil {
			t.Fatal(err)
		}
	}
	gone := func(b *browser, what string) {
		t.Helper()
		resp, _ := b.do("GET", "/ui/bindings", nil, "HX-Request", "")
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/ui/login" {
			t.Errorf("%s: %d %v", what, resp.StatusCode, resp.Header)
		}
	}
	signed := func() *browser {
		b := v.browser(t)
		b.signIn("right")
		b.page()
		return b
	}
	if resp, _ := v.browser(t).do("GET", "/ui/bindings", nil); resp.StatusCode != 200 || resp.Header.Get("HX-Redirect") != "/ui/login" {
		t.Errorf("anonymous htmx request: %d %v", resp.StatusCode, resp.Header)
	}

	b := signed()
	shift("last_seen_at", "31 minutes")
	gone(b, "idle for 31 minutes")
	b = signed()
	if _, err := v.owner.Exec(ctx, "UPDATE admin_sessions SET expires_at = now() - interval '1 second' WHERE username = $1 AND revoked_at IS NULL",
		v.user); err != nil {
		t.Fatal(err)
	}
	gone(b, "past the absolute timeout")

	// the roles change: the token rotates, the old one is dead
	b = signed()
	old := b.csrf
	jarBefore := b.client.Jar.Cookies(mustURL(v.srv.URL))
	v.dir.groups[v.user] = []string{viewers, operators}
	shift("authz_checked_at", "6 minutes")
	resp, _ := b.page()
	if c := cookieOf(resp, sessionCookie); resp.StatusCode != 200 || c == nil || b.csrf == old {
		t.Errorf("rotation: %d %+v", resp.StatusCode, c)
	}
	stale := v.browser(t)
	stale.client.Jar.SetCookies(mustURL(v.srv.URL), jarBefore)
	gone(stale, "the rotated-out token")
	var roles string
	if err := v.owner.QueryRow(ctx, `SELECT roles::text FROM admin_sessions WHERE username = $1 AND revoked_at IS NULL AND expires_at > now()`, v.user).Scan(&roles); err != nil ||
		!strings.Contains(roles, `"operator"`) {
		t.Errorf("rotated session roles: %s %v", roles, err)
	}

	// the directory is down at the re-check: fail closed with 503
	shift("authz_checked_at", "6 minutes")
	v.dir.down = true
	if resp, _ := b.page(); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("directory down: %d", resp.StatusCode)
	}
	v.dir.down = false

	// AC-17: removed from every group, the next request revokes the session
	v.dir.groups[v.user] = nil
	before := v.audits(t, "SESSION_REVOKED")
	gone(b, "AC-17")
	if v.audits(t, "SESSION_REVOKED") != before+1 {
		t.Error("AC-17: SESSION_REVOKED not audited")
	}

	v.dir.groups[v.user] = []string{viewers}
	b = signed()
	resp, _ = b.do("POST", "/ui/logout", nil)
	if c := cookieOf(resp, sessionCookie); resp.StatusCode != 200 || resp.Header.Get("HX-Redirect") != "/ui/login" || c == nil || c.MaxAge >= 0 {
		t.Errorf("logout: %d %v", resp.StatusCode, resp.Header)
	}
	if v.audits(t, "SESSION_LOGOUT") != 1 {
		t.Error("logout not audited")
	}
	var live int
	if err := v.owner.QueryRow(ctx, `SELECT count(*) FROM admin_sessions WHERE username = $1 AND revoked_at IS NULL AND expires_at > now()`, v.user).Scan(&live); err != nil || live != 0 {
		t.Errorf("live sessions after logout: %d %v", live, err)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
