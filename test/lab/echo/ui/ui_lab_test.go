//go:build uilab

// Package ui drives the lab's web UI in headless Chrome, doing what the
// human steps of the echo guide do (.specs/ligo-echo-target.md): carol
// registers a source and requests access, dave approves, carol revokes. It
// runs on the lab host, in two phases between which lab.sh echo ui-smoke
// runs the echo client (ECHO_UI_PHASE=request, then revoke).
package ui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// env reads a setting lab.sh passes.
func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: run this with lab.sh echo ui-smoke", name)
	}
	return v
}

// browser is one user's Chrome, with its own profile, so that the sessions
// of carol and dave never mix.
type browser struct {
	t    *testing.T
	ctx  context.Context
	base string
}

func chrome(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Fatal("no Chrome or Chromium on this machine")
	return ""
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome(t)), chromedp.IgnoreCertErrors) // ligo's certificate is its SVID
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(alloc)
	ctx, cancelTimeout := context.WithTimeout(ctx, 3*time.Minute)
	t.Cleanup(func() { cancelTimeout(); cancel(); cancelAlloc() })
	return &browser{t: t, ctx: ctx, base: strings.TrimSuffix(env(t, "ECHO_UI_URL"), "/")}
}

func (b *browser) do(a chromedp.Action[chromedp.Void]) {
	b.t.Helper()
	if _, err := chromedp.Run(b.ctx, a); err != nil {
		b.t.Fatal(err)
	}
}

func (b *browser) eval(js string) string {
	b.t.Helper()
	v, err := chromedp.Run(b.ctx, chromedp.Evaluate[string](js))
	if err != nil {
		b.t.Fatalf("%s: %v", js, err)
	}
	return v
}

// wait polls a JavaScript predicate until it holds.
func (b *browser) wait(what, predicate string) {
	b.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if b.eval("String(Boolean("+predicate+"))") == "true" {
			return
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("timed out waiting for %s (%s); at %s", what, predicate, b.eval("location.href"))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// arm makes hx-confirm dialogs answer yes: htmx asks with window.confirm,
// and a page load resets it.
func (b *browser) arm() { b.eval(`(window.confirm = () => true, "armed")`) }

func (b *browser) goTo(path string) {
	b.t.Helper()
	b.do(chromedp.Navigate(b.base + path))
	b.wait("the page", `document.readyState === "complete"`)
	b.arm()
}

// waitPath waits for a navigation (an HX-Redirect) to a path with prefix.
func (b *browser) waitPath(prefix string) string {
	b.t.Helper()
	b.wait("the page "+prefix, fmt.Sprintf(`location.pathname.startsWith(%q) && document.readyState === "complete"`, prefix))
	b.arm()
	return b.eval("location.pathname")
}

func (b *browser) click(selector string) {
	b.t.Helper()
	find := fmt.Sprintf(`document.querySelector(%q)`, selector)
	if strings.HasPrefix(selector, "//") { // querySelector throws on XPath
		find = fmt.Sprintf(`document.evaluate(%q, document, null, 9, null).singleNodeValue`, selector)
	}
	b.wait(selector, find)
	b.do(chromedp.Click(selector))
}

func (b *browser) set(selector, value string) {
	b.t.Helper()
	b.wait(selector, fmt.Sprintf(`document.querySelector(%q)`, selector))
	b.do(chromedp.SetValue(selector, value))
}

// login signs in through the login form.
func (b *browser) login(user string) {
	b.t.Helper()
	b.goTo("/ui/login")
	b.set("#username", user)
	b.set("#password", env(b.t, "ECHO_UI_PASSWORD_"+user))
	b.click("#login button[type=submit]")
	b.waitPath("/ui/bindings")
	b.t.Logf("%s signed in", user)
}

// registerSource fills the source form and submits it; the change request
// it lands on is returned.
func (b *browser) registerSource(name, regex, sample string) string {
	b.t.Helper()
	b.goTo("/ui/sources/new-form")
	b.set("#s-name", name)
	b.set("#s-td", "prod.lab")
	b.set("#s-regex", regex)
	b.set("#s-samples", sample)
	b.click("#source button[type=submit]")
	return b.waitPath("/ui/change-requests/")
}

// requestAccess goes through the wizard from the catalog card: the level,
// the source, the review and the submission.
func (b *browser) requestAccess(target, source string) string {
	b.t.Helper()
	b.goTo("/ui/catalog/" + target)
	b.click(`//a[normalize-space()='Request access']`)
	b.wait("step 2", `document.querySelector('#w-level')`)
	b.set("#w-level", "echo")
	b.click(`//button[normalize-space()='Next']`)
	b.wait("step 3", `document.querySelector('input[name=source]')`)
	b.click(fmt.Sprintf(`input[name=source][value=%q]`, source))
	b.click(`//button[normalize-space()='Next']`)
	b.wait("step 4", `document.querySelector('#w-purpose')`)
	b.set("#w-purpose", "echo ui-smoke")
	b.click(`//button[normalize-space()='Review']`)
	b.wait("the review", `document.querySelector('#w-name') && document.querySelector('#binding-check .card')`)
	b.t.Logf("the binding is named %s", b.eval(`document.querySelector('#w-name').value`))
	b.click(`//button[normalize-space()='Submit the request']`)
	return b.waitPath("/ui/change-requests/")
}

// approveAll approves every side of the change request at path until it is
// applied.
func (b *browser) approveAll(path string) {
	b.t.Helper()
	b.goTo(path)
	status := `(document.querySelector('#cr-decision dl .badge') || {}).textContent`
	for i := 0; i < 6; i++ {
		if b.eval(status) == "APPLIED" {
			b.t.Logf("%s is APPLIED", path)
			return
		}
		before := b.eval(`document.getElementById('cr-decision').innerHTML`)
		b.click("#cr-approve button[type=submit]")
		b.wait("the decision", fmt.Sprintf(`document.getElementById('cr-decision').innerHTML !== %q`, before))
	}
	if b.eval(status) != "APPLIED" {
		b.t.Fatalf("%s is %s after the approvals", path, b.eval(status))
	}
}

// TestUISmoke is the human part of the echo guide, in the phase lab.sh asks
// for.
func TestUISmoke(t *testing.T) {
	phase := os.Getenv("ECHO_UI_PHASE")
	if phase == "" {
		t.Skip("ECHO_UI_PHASE is not set: run this with lab.sh echo ui-smoke")
	}
	target, source, binding := env(t, "ECHO_UI_TARGET"), env(t, "ECHO_UI_SOURCE"), env(t, "ECHO_UI_BINDING")
	carol, dave := newBrowser(t), newBrowser(t)
	carol.login("carol")
	dave.login("dave")
	switch phase {
	case "request":
		if os.Getenv("ECHO_UI_REGISTER_SOURCE") == "1" {
			cr := carol.registerSource(source, `^spiffe://prod\.lab/ns/echo/sa/bound$`, "spiffe://prod.lab/ns/echo/sa/bound")
			dave.approveAll(cr)
		}
		dave.approveAll(carol.requestAccess(target, source))
	case "revoke":
		carol.goTo("/ui/bindings/" + binding)
		carol.click(`//button[normalize-space()='Revoke']`)
		carol.wait("the revocation", `location.pathname.startsWith("/ui/change-requests/") || location.pathname === "/ui/bindings"`)
		if path := carol.eval("location.pathname"); strings.HasPrefix(path, "/ui/change-requests/") {
			dave.approveAll(path)
		}
	default:
		t.Fatalf("ECHO_UI_PHASE %q: request or revoke", phase)
	}
}
