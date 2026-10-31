package ui

import (
	"encoding/base64"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/targets"
	"github.com/dihedron/ligo/internal/theme"
	"github.com/dihedron/ligo/web"
	"golang.org/x/net/html"
)

func newServer(t *testing.T) *Server {
	t.Helper()
	th, err := theme.Load(theme.Files{Directory: t.TempDir(), Colors: map[string]map[string]string{"light": {"primary": "#1f4e8c"}}}, theme.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(th, config.Theme{DefaultMode: "system", ProductName: "ligo"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var cspNonce = regexp.MustCompile(`script-src 'self' 'nonce-([A-Za-z0-9+/=]+)'`)

// TestSecurityHeaders: every /ui/ response, found or not, carries the §7.4
// headers with its own 16-byte nonce; theme assets alone are cacheable.
func TestSecurityHeaders(t *testing.T) {
	h := newServer(t).Handler()
	seen := map[string]bool{}
	for _, path := range []string{"/ui/static/htmx.min.js", "/ui/static/ext/hx-csp.min.js", "/ui/static/app.js", "/ui/static/styles.css",
		"/ui/nope", "/ui/static/ext/", "/ui/static/VERSIONS", "/ui/theme/tokens.css"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		hd := rec.Header()
		m := cspNonce.FindStringSubmatch(hd.Get("Content-Security-Policy"))
		if m == nil {
			t.Fatalf("%s: CSP %q", path, hd.Get("Content-Security-Policy"))
		}
		if raw, err := base64.StdEncoding.DecodeString(m[1]); err != nil || len(raw) != 16 || seen[m[1]] {
			t.Errorf("%s: nonce %q not fresh 16 bytes", path, m[1])
		}
		seen[m[1]] = true
		if hd.Get("Content-Security-Policy") != policy(m[1]) || hd.Get("X-Content-Type-Options") != "nosniff" ||
			hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("Strict-Transport-Security") != "max-age=31536000" || hd.Get("X-Request-Id") == "" {
			t.Errorf("%s: headers %v", path, hd)
		}
		want := "no-store"
		if strings.HasPrefix(path, "/ui/theme/") {
			want = "public, max-age=3600"
		}
		if hd.Get("Cache-Control") != want {
			t.Errorf("%s: Cache-Control %q", path, hd.Get("Cache-Control"))
		}
		wantCode := 200
		switch path {
		case "/ui/static/ext/", "/ui/static/VERSIONS":
			wantCode = 404
		case "/ui/nope":
			wantCode = http.StatusSeeOther // behind the session: anonymous requests go to the login page first
		}
		if rec.Code != wantCode {
			t.Errorf("%s: %d, want %d", path, rec.Code, wantCode)
		}
	}
}

// fixture registers a test page using the layout, and renders it for r.
func render(t *testing.T, s *Server, r *http.Request, p Page) (*httptest.ResponseRecorder, string) {
	t.Helper()
	if _, ok := s.pages.page["test"]; !ok {
		if err := s.pages.add("test", `{{define "content"}}<button hx-get="/ui/x" {{hxnonce}}>go</button>{{end}}`); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	s.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.page(w, r, 200, "test", p) })).ServeHTTP(rec, r)
	m := cspNonce.FindStringSubmatch(rec.Header().Get("Content-Security-Policy"))
	return rec, m[1]
}

// TestLayout: the page's scripts and hx-* elements carry the response's
// nonce; the htmx-config, the CSRF meta, the banners and the color mode
// follow the data and the cookie (§7.4, §7.6).
func TestLayout(t *testing.T) {
	s := newServer(t)
	rec, n := render(t, s, httptest.NewRequest("GET", "/ui/test", nil), Page{Title: "Test", CSRF: "tok", User: "olga",
		Nav: []NavItem{{Path: "/ui/bindings", Label: "Bindings", Current: true}}, Maintenance: &Maintenance{Reason: "upgrade"},
		BreakGlass: []OpenBreakGlass{{Name: "bg-1", ExpiresIn: "2h"}}})
	body := rec.Body.String()
	// the nonce is base64: html/template may write its + as &#43;, so compare parsed attributes
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var scripts []string
	for node := range doc.Descendants() {
		if node.Type == html.ElementNode && node.Data == "script" {
			attrs := map[string]string{}
			for _, a := range node.Attr {
				attrs[a.Key] = a.Val
			}
			if attrs["nonce"] != n {
				t.Errorf("script %s: nonce %q, want %q", attrs["src"], attrs["nonce"], n)
			}
			scripts = append(scripts, attrs["src"])
		}
	}
	if strings.Join(scripts, " ") != "/ui/static/htmx.min.js /ui/static/ext/hx-csp.min.js /ui/static/app.js" {
		t.Errorf("scripts: %v", scripts)
	}
	for _, want := range []string{
		`<button hx-get="/ui/x" hx-nonce="` + template.HTMLEscapeString(n) + `">go</button>`,
		`<meta name="csrf-token" content="tok">`,
		`<meta name="htmx-config" content="{&#34;defaultTimeout&#34;:90000,&#34;extensions&#34;:&#34;hx-csp&#34;,&#34;history&#34;:true,` +
			`&#34;implicitInheritance&#34;:false,&#34;includeIndicatorCSS&#34;:false,&#34;mode&#34;:&#34;same-origin&#34;,&#34;noSwap&#34;:[204,304,&#34;5xx&#34;]}">`,
		`<link rel="stylesheet" href="/ui/theme/tokens.css">`, `<title>Test · ligo</title>`, `<html lang="en">`,
		"Maintenance mode is on: upgrade.", "<li>bg-1, expires in 2h</li>", `aria-current="page"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if strings.Contains(body, "/ui/theme/theme.css") || strings.Contains(body, "/ui/theme/logo") {
		t.Error("absent theme files are referenced")
	}
	for cookie, want := range map[string]string{"dark": ` data-theme="dark"`, "light": ` data-theme="light"`, "system": `<html lang="en">`,
		"sepia": `<html lang="en">`} {
		r := httptest.NewRequest("GET", "/ui/test", nil)
		r.AddCookie(&http.Cookie{Name: "__Host-ligo_theme", Value: cookie})
		if rec, _ := render(t, s, r, Page{User: "olga"}); !strings.Contains(rec.Body.String(), want) {
			t.Errorf("cookie %s: no %s", cookie, want)
		}
	}
	s.ThemeConfig.DefaultMode = "dark"
	if rec, _ := render(t, s, httptest.NewRequest("GET", "/ui/test", nil), Page{}); !strings.Contains(rec.Body.String(), ` data-theme="dark"`) {
		t.Error("default_mode dark")
	}
}

// TestAlertAndRedirect: 409/422 alerts land in the form's container, others
// are retargeted to the page's; mutations navigate with HX-Redirect.
func TestAlertAndRedirect(t *testing.T) {
	s := newServer(t)
	for code, retarget := range map[int]string{409: "", 422: "", 403: "#page-errors"} {
		rec := httptest.NewRecorder()
		s.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.alert(w, r, code, "No <b>way</b>") })).ServeHTTP(rec,
			httptest.NewRequest("POST", "/ui/x", nil))
		body := rec.Body.String()
		if rec.Code != code || rec.Header().Get("HX-Retarget") != retarget || !strings.Contains(body, "No &lt;b&gt;way&lt;/b&gt;") ||
			!strings.Contains(body, rec.Header().Get("X-Request-Id")) {
			t.Errorf("%d: %v %s", code, rec.Header(), body)
		}
	}
	rec := httptest.NewRecorder()
	redirect(rec, "/ui/bindings")
	if rec.Code != 200 || rec.Header().Get("HX-Redirect") != "/ui/bindings" {
		t.Errorf("redirect: %d %v", rec.Code, rec.Header())
	}
}

// TestTemplates renders every page and fragment: each element with an hx-*
// attribute carries hx-nonce, the response's nonce, which templates write
// only through hxnonce; fragments contain no <script> (§7.4, T-05).
func TestTemplates(t *testing.T) {
	err := fs.WalkDir(web.FS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		src, _ := fs.ReadFile(web.FS, path)
		if strings.Contains(string(src), "hx-nonce") {
			t.Errorf("%s writes hx-nonce by hand; use {{hxnonce}}", path)
		}
		if strings.HasPrefix(path, "templates/fragments/") && strings.Contains(strings.ToLower(string(src)), "<script") {
			t.Errorf("%s: a fragment contains <script>", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(t)
	full := Page{Title: "t", CSRF: "c", User: "u", Nav: []NavItem{{Path: "/ui/a", Label: "a"}}, Maintenance: &Maintenance{},
		BreakGlass: []OpenBreakGlass{{Name: "b"}}}
	check := func(what string, rec *httptest.ResponseRecorder) {
		n := cspNonce.FindStringSubmatch(rec.Header().Get("Content-Security-Policy"))[1]
		doc, err := html.Parse(strings.NewReader(rec.Body.String()))
		if err != nil {
			t.Fatal(err)
		}
		for node := range doc.Descendants() {
			if node.Type != html.ElementNode {
				continue
			}
			hx, nonce := false, ""
			for _, a := range node.Attr {
				switch {
				case a.Key == "hx-nonce":
					nonce = a.Val
				case strings.HasPrefix(a.Key, "hx-"):
					hx = true
				}
			}
			if hx && nonce != n {
				t.Errorf("%s: <%s> has hx-* attributes and hx-nonce %q, want %q", what, node.Data, nonce, n)
			}
		}
	}
	if err := s.pages.add("probe", `{{define "content"}}{{end}}`); err != nil {
		t.Fatal(err)
	}
	samples := samples()
	for name := range s.pages.page {
		rec := httptest.NewRecorder()
		p := full
		p.Content = samples[name]
		s.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.page(w, r, 200, name, p) })).ServeHTTP(rec,
			httptest.NewRequest("GET", "/ui/x", nil))
		if rec.Code != 200 {
			t.Errorf("page %s: %d", name, rec.Code)
		}
		check("page "+name, rec)
	}
	for _, tmpl := range s.pages.fragment.Templates() {
		name := tmpl.Name()
		if name == "ui" || strings.HasSuffix(name, ".html") {
			continue
		}
		rec := httptest.NewRecorder()
		data, ok := samples[name]
		if !ok {
			t.Errorf("fragment %s has no sample data in samples()", name)
		}
		s.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.fragment(w, r, 200, name, data) })).ServeHTTP(rec,
			httptest.NewRequest("GET", "/ui/x", nil))
		if rec.Code != 200 {
			t.Errorf("fragment %s: %d", name, rec.Code)
		}
		check("fragment "+name, rec)
		if b, _ := io.ReadAll(rec.Body); strings.Contains(strings.ToLower(string(b)), "<script") {
			t.Errorf("fragment %s renders <script>", name)
		}
	}
}

// samples are representative data for every page and fragment, so that
// TestTemplates renders their hx-* elements.
func samples() map[string]any {
	id := uuid.NewV7()
	now := time.Now()
	v := &bindings.View{Source: "s", Target: "t", AccessLevel: "read", ExpiresAt: &now, Spec: []byte(`{"host":"db"}`), Auth: []byte(`{}`)}
	v.Metadata.Name, v.Metadata.ActiveRevision, v.Status.Phase, v.Status.PendingChangeRequestID = "b", new(int64), "PROVISIONING", &id
	v.Status.BreakGlass = &bindings.BreakGlassStatus{ChangeRequestID: id, ExpiresAt: now}
	v.Active = &bindings.ViewActive{SVIDRegex: "^x$", Since: now}
	row := StatusRow{Name: "b", Phase: "PROVISIONING", Polling: true, Steps: []Step{{Number: 1, Name: "Identity", State: "done"}}}
	cr := &changerequests.Request{ID: id, ResourceType: "BINDING", ResourceName: "b", Operation: "UPDATE", Status: "PENDING", Payload: []byte(`{}`),
		Sides: []changerequests.Side{{Name: "SOURCE", Scope: "dc/x"}, {Name: "TARGET", Decision: "APPROVED", DecidedAt: &now}}}
	trail := []Entry{{Action: "BINDING_CREATED", Actor: "olga", Revision: new(int64), OccurredAt: now}}
	src := &sources.View{Source: sources.Source{DisplayName: "d", Labels: map[string]string{"k": "v"}, Contacts: []sources.Contact{{Name: "n", Email: "e"}},
		Identity: sources.Identity{SampleSPIFFEIDs: []string{"spiffe://x/y"}}}}
	src.Metadata.Name, src.Metadata.State, src.Metadata.PendingChangeRequestID = "s", "ACTIVE", &id
	tgt := &targets.View{Target: targets.Target{Definition: []byte(`{}`), DocumentationURL: "https://docs.example", AccessLevels: []targets.AccessLevel{{Name: "read"}}}}
	tgt.Metadata.Name, tgt.Metadata.State = "t", "ACTIVE"
	return map[string]any{
		"login":    map[string]string{"Prelogin": "p"},
		"bindings": Dashboard{Phases: phases, Bindings: []*bindings.View{v}, Next: "b", AwaitingMe: []*changerequests.Request{cr}},
		"binding": BindingPage{Binding: v, Row: row, Stages: []bindings.Stage{{Stage: "TARGET", Status: "ENSURED"}}, Audit: trail,
			Flows: []flows.Flow{{Name: "f", Ports: []flows.Port{{Low: 1, High: 1}}, TLS: true}}},
		"change-requests": Requests{Requests: []*changerequests.Request{cr}, Next: id.String()},
		"change-request":  RequestPage{Request: cr, Decision: Decision{Request: cr, Eligible: []string{"SOURCE", "TARGET"}, CanWithdraw: true}, Diff: map[string]any{"changes": []any{}}},
		"cr-decision":     Decision{Request: cr, Eligible: []string{"SOURCE"}, CanWithdraw: true, Disabled: true},
		"error":           Alert{Message: "m"},
		"alert":           Alert{Message: "m"},
		"status-row":      row,
		"trail":           trail,
		"bindings-table":  []*bindings.View{v},
		"flows-table":     []flows.Flow{{Name: "f", Ports: []flows.Port{{Low: 1, High: 1}}}},
		"levels-table":    []targets.AccessLevel{{Name: "read", Privileges: []string{"role:R"}, State: "ACTIVE"}},
		"sources":         SourcesPage{Sources: []*sources.View{src}, Next: "s"},
		"source":          SourcePage{Source: src, Bindings: []*bindings.View{v}, Audit: trail},
		"targets":         TargetsPage{Targets: []*targets.View{tgt}, Next: "t"},
		"target":          TargetPage{Target: tgt, Bindings: []*bindings.View{v}, Audit: trail},
		"platforms":       []PlatformRow{{Name: "p", Serving: true, Health: "serving", TargetScopes: []string{"dc/x/*"}}},
		"catalog":         CatalogPage{Types: []string{"oracle.v1"}, Targets: []catalog.Target{{Name: "t", State: "DEPRECATED"}}, Next: "t"},
		"catalog-card":    CardPage{Target: tgt, Flows: []flows.Flow{{Name: "f"}}, FlowsJSON: "{}", Outcomes: []catalog.Outcome{{Source: "s", Allowed: true, Sides: []string{"TARGET"}}}},
	}
}
