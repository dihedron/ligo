package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/theme"
)

// tab is a headless Chrome tab that records CSP violations and htmx's
// stripped attributes from the first line of every document.
type tab struct {
	t   *testing.T
	ctx context.Context
}

func newTab(t *testing.T, dark bool) *tab {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome(t)), chromedp.IgnoreCertErrors)
	if os.Getenv("CI") != "" {
		opts = append(opts, chromedp.NoSandbox)
	}
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(cancelAlloc)
	ctx, cancel := chromedp.NewContext(alloc)
	t.Cleanup(cancel)
	ctx, cancelTimeout := context.WithTimeout(ctx, 2*time.Minute)
	t.Cleanup(cancelTimeout)
	b := &tab{t: t, ctx: ctx}
	if _, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: `window.cspViolations = []; window.stripped = 0;
		document.addEventListener("securitypolicyviolation", e => window.cspViolations.push(e.violatedDirective + " " + e.blockedURI));
		document.addEventListener("htmx:security:strip", () => window.stripped++);`}); err != nil {
		t.Fatal(err)
	}
	if dark {
		if _, err := chromedp.Call(ctx, emulation.SetEmulatedMedia, emulation.SetEmulatedMediaParams{Features: []*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: "dark"}}}); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func (b *tab) do(a chromedp.Action[chromedp.Void]) {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(b.ctx, 20*time.Second)
	defer cancel()
	if _, err := chromedp.Run(ctx, a); err != nil {
		state, _ := chromedp.Run(b.ctx, chromedp.Evaluate[string](`window.cspViolations.join("; ") + "\n" + document.body.innerHTML`))
		b.t.Fatalf("%v; the page: %s", err, state)
	}
}

func (b *tab) text(expr string) string {
	b.t.Helper()
	v, err := chromedp.Run(b.ctx, chromedp.Evaluate[string](expr))
	if err != nil {
		b.t.Fatalf("%s: %v", expr, err)
	}
	return v
}

func (b *tab) violations() string {
	b.t.Helper()
	return b.text(`window.cspViolations.join("; ")`)
}

// tlsServer serves the UI's own routes, and the test's where more specific.
func tlsServer(t *testing.T, s *Server, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/ui/", s.Handler())
	for pattern, h := range routes {
		mux.Handle(pattern, s.secure(h))
	}
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// onePixel is a real PNG: the browser decodes it.
var onePixel = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89" +
	"\x00\x00\x00\rIDATx\x9cc\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff\x89\x99=\x1d\x00\x00\x00\x00IEND\xaeB`\x82")

const scriptedLogo = `<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><script>window.pwned = true</script></svg>`

// themed is a server whose theme directory holds these files.
func themed(t *testing.T, files map[string][]byte) *Server {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	th, err := theme.Load(theme.Files{Directory: dir}, theme.Options{OwnerUID: uint32(os.Getuid())}) //nolint:gosec // a uid fits
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(th, config.Theme{DefaultMode: "system", ProductName: "ligo"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestThemeBrowser: the custom stylesheet applies, and the logo follows the
// color mode: the dark one in dark mode (AC-39). With no cookie the dark
// tokens apply; choosing light persists, with no inline script and no CSP
// violation (AC-41).
func TestThemeBrowser(t *testing.T) {
	s := themed(t, map[string][]byte{"theme.css": []byte(":root { --custom-mark: applied; }"),
		"logo.svg": []byte(scriptedLogo), "logo-dark.png": onePixel})
	if err := s.pages.add("harness", `{{define "content"}}<p id="ready">ready</p>{{end}}`); err != nil {
		t.Fatal(err)
	}
	srv := tlsServer(t, s, map[string]http.HandlerFunc{
		"GET /ui/test": func(w http.ResponseWriter, r *http.Request) {
			s.page(w, r, 200, "harness", Page{Title: "harness", CSRF: "c", User: "olga"})
		},
		"POST /ui/preferences/theme": s.preference, // without the session middleware
	})
	shownLogo := `[...document.querySelectorAll("img.logo-light, img.logo-dark")].filter(e => e.getClientRects().length > 0).map(e => e.getAttribute("src")).join(" ")`
	bg := `getComputedStyle(document.documentElement).getPropertyValue("--color-bg").trim()`

	light := newTab(t, false)
	light.do(chromedp.Navigate(srv.URL + "/ui/test"))
	light.do(chromedp.WaitVisible(chromedp.ID("ready")))
	if got := light.text(shownLogo); got != "/ui/theme/logo" {
		t.Errorf("light mode shows %q", got)
	}
	lightBG := light.text(bg)
	if got := light.text(`getComputedStyle(document.documentElement).getPropertyValue("--custom-mark").trim()`); got != "applied" {
		t.Errorf("theme.css: %q", got)
	}

	dark := newTab(t, true)
	dark.do(chromedp.Navigate(srv.URL + "/ui/test"))
	dark.do(chromedp.WaitVisible(chromedp.ID("ready")))
	if got := dark.text(shownLogo); got != "/ui/theme/logo-dark" {
		t.Errorf("dark mode shows %q", got)
	}
	if dark.text(bg) == lightBG || dark.text(`String(document.documentElement.hasAttribute("data-theme"))`) != "false" {
		t.Errorf("dark tokens: %q, light %q", dark.text(bg), lightBG)
	}
	if n := dark.text(`String(document.querySelectorAll("script:not([src])").length)`); n != "0" {
		t.Errorf("%s inline scripts", n)
	}
	dark.text(`(() => { const m = document.getElementById("theme-mode"); m.value = "light";
		m.dispatchEvent(new Event("change", {bubbles: true})); return ""; })()`)
	dark.do(chromedp.WaitVisible(chromedp.CSS(`html[data-theme="light"] #ready`)))
	if got := dark.text(bg); got != lightBG {
		t.Errorf("after choosing light: %q, want %q", got, lightBG)
	}
	if got := dark.text(shownLogo); got != "/ui/theme/logo" {
		t.Errorf("after choosing light, shows %q", got)
	}
	if v := dark.violations(); v != "" {
		t.Errorf("CSP violations: %s", v)
	}
	// a new tab of the same browser keeps the choice; the cookie outlives the session
	dark.do(chromedp.Navigate(srv.URL + "/ui/test"))
	dark.do(chromedp.WaitVisible(chromedp.CSS(`html[data-theme="light"] #ready`)))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/ui/preferences/theme", strings.NewReader("mode=light"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.preference(rec, r)
	if c := rec.Header().Get("Set-Cookie"); !strings.Contains(c, "Max-Age=31536000") {
		t.Errorf("cookie %s", c)
	}
}

// TestLogoSandboxBrowser: a script in logo.svg does not run when the logo is
// opened directly; the same document served without the sandbox CSP does
// (AC-42).
func TestLogoSandboxBrowser(t *testing.T) {
	s := themed(t, map[string][]byte{"logo.svg": []byte(scriptedLogo)})
	mux := http.NewServeMux()
	mux.Handle("/ui/", s.Handler())
	mux.HandleFunc("GET /control.svg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write([]byte(scriptedLogo))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	b := newTab(t, false)
	b.do(chromedp.Navigate(srv.URL + "/control.svg"))
	if got := b.text(`String(window.pwned === true)`); got != "true" {
		t.Fatalf("the control did not run its script: %s", got)
	}
	b.do(chromedp.Navigate(srv.URL + "/ui/theme/logo"))
	if got := b.text(`String(window.pwned === true)`); got != "false" {
		t.Errorf("the logo ran its script")
	}
}

// TestAlteredFragmentBrowser: buttons injected in transit, one with no nonce
// and one with a copy of the page's, are stripped and send nothing. A CSP
// that forbids the htmx policy stops all processing, so it fails closed; and
// no page reports a CSP violation (AC-82).
func TestAlteredFragmentBrowser(t *testing.T) {
	s := newServer(t)
	if err := s.pages.add("harness", `{{define "content"}}
<button id="load" hx-get="/ui/test/fragment" hx-target="#out" hx-swap="innerHTML" {{hxnonce}}>load</button>
<div id="out"></div>{{end}}`); err != nil {
		t.Fatal(err)
	}
	var pageNonce atomic.Value
	var rotated atomic.Int32
	s2 := samples()
	routes := map[string]http.HandlerFunc{
		"GET /ui/test": func(w http.ResponseWriter, r *http.Request) {
			pageNonce.Store(Nonce(r.Context()))
			s.page(w, r, 200, "harness", Page{Title: "harness", CSRF: "c"})
		},
		"GET /ui/test/fragment": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, `<p id="loaded">loaded</p>
<button id="bare" hx-post="/ui/test/rotate" hx-target="#out">bare</button>
<button id="copied" hx-post="/ui/test/rotate" hx-target="#out" hx-nonce="%s">copied</button>`, pageNonce.Load())
		},
		"POST /ui/test/rotate": func(http.ResponseWriter, *http.Request) { rotated.Add(1) },
		"GET /ui/test/disabled": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", strings.Replace(w.Header().Get("Content-Security-Policy"), "trusted-types htmx", "trusted-types other", 1))
			s.page(w, r, 200, "harness", Page{Title: "harness", CSRF: "c"})
		},
		"GET /ui/test/page/{name}": func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			s.page(w, r, 200, name, Page{Title: "t", CSRF: "c", User: "u", Nav: []NavItem{{Path: "/ui/a", Label: "a"}},
				Maintenance: &Maintenance{}, BreakGlass: []OpenBreakGlass{{Name: "b", CanAct: true}}, Content: s2[name]})
		},
	}
	srv := tlsServer(t, s, routes)

	b := newTab(t, false)
	b.do(chromedp.Navigate(srv.URL + "/ui/test"))
	b.do(chromedp.WaitVisible(chromedp.ID("load")))
	b.do(chromedp.Click(chromedp.ID("load")))
	b.do(chromedp.WaitVisible(chromedp.ID("loaded")))
	b.do(chromedp.Click(chromedp.ID("bare")))
	b.do(chromedp.Click(chromedp.ID("copied")))
	b.do(chromedp.Sleep(500 * time.Millisecond))
	if n := rotated.Load(); n != 0 {
		t.Errorf("%d requests from injected buttons", n)
	}
	if got := b.text(`String(document.querySelectorAll("#bare[hx-post], #copied[hx-post], #copied[hx-nonce]").length)`); got != "0" {
		t.Errorf("%s injected elements keep htmx attributes", got)
	}
	if got := b.text(`String(window.stripped)`); got == "0" {
		t.Error("htmx:security:strip was not raised")
	}

	off := newTab(t, false)
	off.do(chromedp.Navigate(srv.URL + "/ui/test/disabled"))
	off.do(chromedp.WaitVisible(chromedp.ID("load")))
	off.do(chromedp.Click(chromedp.ID("load")))
	off.do(chromedp.Sleep(500 * time.Millisecond))
	if got := off.text(`String(document.getElementById("loaded") !== null)`); got != "false" {
		t.Error("htmx processed a page whose CSP forbids its policy")
	}

	every := newTab(t, false)
	for name := range s.pages.page {
		every.do(chromedp.Navigate(srv.URL + "/ui/test/page/" + name))
		every.do(chromedp.Sleep(200 * time.Millisecond))
		if v := every.violations(); v != "" {
			t.Errorf("page %s: CSP violations: %s", name, v)
		}
	}
}

// TestErrorsBrowser: 409 and 422 land in the form's container, 403 in the
// page's; a 500 replaces nothing and shows the banner with its request ID
// (AC-83).
func TestErrorsBrowser(t *testing.T) {
	s := newServer(t)
	if err := s.pages.add("harness", `{{define "content"}}
<div id="form-errors"></div><p id="kept">kept</p>
{{range .Content}}<button id="b{{.}}" hx-post="/ui/test/fail/{{.}}" hx-target="#kept" hx-swap="outerHTML"
 hx-status:409="target:#form-errors swap:innerHTML" hx-status:422="target:#form-errors swap:innerHTML" {{hxnonce}}>{{.}}</button>{{end}}{{end}}`); err != nil {
		t.Fatal(err)
	}
	var lastID atomic.Value
	srv := tlsServer(t, s, map[string]http.HandlerFunc{
		"GET /ui/test": func(w http.ResponseWriter, r *http.Request) {
			s.page(w, r, 200, "harness", Page{Title: "harness", CSRF: "c", Content: []int{409, 422, 403, 500}})
		},
		"POST /ui/test/fail/{code}": func(w http.ResponseWriter, r *http.Request) {
			var code int
			_, _ = fmt.Sscan(r.PathValue("code"), &code)
			lastID.Store(w.Header().Get("X-Request-Id"))
			s.alert(w, r, code, fmt.Sprintf("refused with %d", code))
		},
	})
	b := newTab(t, false)
	b.do(chromedp.Navigate(srv.URL + "/ui/test"))
	b.do(chromedp.WaitVisible(chromedp.ID("b409")))
	content := func(id string) string {
		t.Helper()
		return b.text(`document.getElementById("` + id + `").textContent`)
	}
	for _, tc := range []struct{ code, where string }{{"409", "form-errors"}, {"422", "form-errors"}, {"403", "page-errors"}} {
		b.do(chromedp.Click(chromedp.ID("b" + tc.code)))
		b.do(chromedp.WaitVisible(chromedp.CSS(`#` + tc.where + `:not(:empty)`)))
		b.do(chromedp.Sleep(100 * time.Millisecond))
		if got := content(tc.where); !strings.Contains(got, "refused with "+tc.code) {
			t.Errorf("%s in #%s: %q", tc.code, tc.where, got)
		}
	}
	before := content("page-errors") + content("form-errors")
	b.do(chromedp.Click(chromedp.ID("b500")))
	b.do(chromedp.WaitVisible(chromedp.ID("error-banner")))
	if got := content("error-banner"); !strings.Contains(got, "(500)") || !strings.Contains(got, lastID.Load().(string)) {
		t.Errorf("banner %q, request ID %v", got, lastID.Load())
	}
	if got := content("page-errors") + content("form-errors"); got != before {
		t.Errorf("a 500 replaced content: %q, was %q", got, before)
	}
	if got := content("kept"); got != "kept" {
		t.Errorf("a 500 swapped: %q", got)
	}
}

// TestPollingBrowser: the final status row stops the polling. The browser
// gives a request 90 s, so a 70 s approval is not cut off, and htmx does
// enforce that setting: a request beyond a shorter timeout is dropped
// (AC-84).
func TestPollingBrowser(t *testing.T) {
	s := newServer(t)
	if err := s.pages.add("harness", `{{define "content"}}{{template "status-row" .Content}}
<button id="slow" hx-post="/ui/test/slow" hx-target="#slow-out" hx-swap="innerHTML" {{hxnonce}}>slow</button><div id="slow-out"></div>{{end}}`); err != nil {
		t.Fatal(err)
	}
	var polls atomic.Int32
	srv := tlsServer(t, s, map[string]http.HandlerFunc{
		"GET /ui/test": func(w http.ResponseWriter, r *http.Request) {
			s.page(w, r, 200, "harness", Page{Title: "harness", CSRF: "c", Content: StatusRow{Name: "b", Phase: "PROVISIONING", Polling: true}})
		},
		"GET /ui/bindings/b/status-row": func(w http.ResponseWriter, r *http.Request) {
			polls.Add(1)
			s.fragment(w, r, 200, "status-row", StatusRow{Name: "b", Phase: "ACTIVE"})
		},
		"POST /ui/test/slow": func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(1500 * time.Millisecond)
			_, _ = w.Write([]byte("done"))
		},
	})
	b := newTab(t, false)
	b.do(chromedp.Navigate(srv.URL + "/ui/test"))
	b.do(chromedp.WaitVisible(chromedp.CSS(`#status-row:not([hx-get])`)))
	b.do(chromedp.Sleep(5 * time.Second)) // more than two polling intervals
	if n := polls.Load(); n != 1 {
		t.Errorf("%d status-row requests, want 1", n)
	}
	if got := b.text(`String(htmx.config.defaultTimeout)`); got != "90000" {
		t.Errorf("defaultTimeout %s", got)
	}
	b.do(chromedp.Click(chromedp.ID("slow")))
	b.do(chromedp.WaitVisible(chromedp.CSS(`#slow-out:not(:empty)`)))
	b.text(`(() => { htmx.config.defaultTimeout = 300; document.getElementById("slow-out").textContent = ""; return ""; })()`)
	b.do(chromedp.Click(chromedp.ID("slow")))
	b.do(chromedp.Sleep(2500 * time.Millisecond))
	if got := b.text(`document.getElementById("slow-out").textContent`); got != "" {
		t.Errorf("a request beyond the timeout was swapped: %q", got)
	}
}

// TestStorageBrowser: navigation, a form and going back leave nothing in
// localStorage or sessionStorage (AC-85).
func TestStorageBrowser(t *testing.T) {
	s := newServer(t)
	if err := s.pages.add("harness", `{{define "content"}}
<a id="next" href="/ui/test/next" hx-get="/ui/test/next" hx-target="#out" hx-swap="innerHTML" hx-push-url="true" {{hxnonce}}>next</a>
<form id="f" hx-post="/ui/test/save" hx-target="#out" {{hxnonce}}><input name="secret" value="page-content"><button id="save">save</button></form>
<div id="out"><p>page-content</p></div>{{end}}`); err != nil {
		t.Fatal(err)
	}
	srv := tlsServer(t, s, map[string]http.HandlerFunc{
		"GET /ui/test": func(w http.ResponseWriter, r *http.Request) {
			s.page(w, r, 200, "harness", Page{Title: "harness", CSRF: "c"})
		},
		"GET /ui/test/next": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<p id="nexted">page-content</p>`))
		},
		"POST /ui/test/save": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<p id="saved">page-content</p>`))
		},
	})
	b := newTab(t, false)
	b.do(chromedp.Navigate(srv.URL + "/ui/test"))
	b.do(chromedp.WaitVisible(chromedp.ID("next")))
	b.do(chromedp.Click(chromedp.ID("save")))
	b.do(chromedp.WaitVisible(chromedp.ID("saved")))
	b.do(chromedp.Click(chromedp.ID("next")))
	b.do(chromedp.WaitVisible(chromedp.ID("nexted")))
	b.text(`(history.back(), "")`)
	b.do(chromedp.Sleep(500 * time.Millisecond))
	if got := b.text(`JSON.stringify([Object.keys(localStorage), Object.keys(sessionStorage)])`); got != "[[],[]]" {
		t.Errorf("browser storage: %s", got)
	}
}

// TestInheritedTargetsBrowser: the forms upgrade-check names keep their
// swaps with hx-target:inherited: the form's own request and the button
// inside it, which sets its own, both replace the whole fragment (AC-85).
func TestInheritedTargetsBrowser(t *testing.T) {
	s := newServer(t)
	if err := s.pages.add("decision", `{{define "content"}}<div id="cr-errors"></div>{{template "cr-decision" .Content}}{{end}}`); err != nil {
		t.Fatal(err)
	}
	if err := s.pages.add("search", `{{define "content"}}{{template "wizard-form" .Content}}{{end}}`); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewV7()
	decision := Decision{Request: &changerequests.Request{ID: id, Status: "PENDING", PayloadSHA256: "abc"}, Eligible: []string{"TARGET"}}
	replaced := func(root, mark string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `<div id="%s"><p id="%s">%s</p></div>`, root, mark, mark)
		}
	}
	srv := tlsServer(t, s, map[string]http.HandlerFunc{
		"GET /ui/test/decision": func(w http.ResponseWriter, r *http.Request) {
			s.page(w, r, 200, "decision", Page{Title: "t", CSRF: "c", Content: decision})
		},
		"GET /ui/test/search": func(w http.ResponseWriter, r *http.Request) {
			s.page(w, r, 200, "search", Page{Title: "t", CSRF: "c", Content: Wizard{Step: 1, Targets: []catalog.Target{{Name: "t"}}}})
		},
		"POST /ui/change-requests/{id}/approve": replaced("cr-decision", "approved"),
		"POST /ui/change-requests/{id}/decline": replaced("cr-decision", "declined"),
		"GET /ui/bindings/wizard":               replaced("wizard", "searched"),
	})
	b := newTab(t, false)
	whole := func(root string) {
		t.Helper()
		if got := b.text(`String(document.querySelectorAll("#` + root + `").length) + document.querySelector("#` + root + `").parentElement.id`); !strings.HasPrefix(got, "1") {
			t.Errorf("#%s: %s", root, got)
		}
		if got := b.text(`String(document.querySelectorAll("#` + root + ` #` + root + `").length)`); got != "0" {
			t.Errorf("#%s swapped inside itself", root)
		}
	}
	for button, mark := range map[string]string{`#cr-approve button[type=submit]`: "approved", `#cr-approve button.button-danger`: "declined"} {
		b.do(chromedp.Navigate(srv.URL + "/ui/test/decision"))
		b.do(chromedp.Click(chromedp.CSS(button)))
		b.do(chromedp.WaitVisible(chromedp.ID(mark)))
		whole("cr-decision")
	}
	b.do(chromedp.Navigate(srv.URL + "/ui/test/search"))
	b.do(chromedp.Click(chromedp.CSS(`#wizard button.button-secondary`)))
	b.do(chromedp.WaitVisible(chromedp.ID("searched")))
	whole("wizard")
}
