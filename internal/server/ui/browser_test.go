package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// chrome finds a Chrome or Chromium binary; CI must have one.
func chrome(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "headless_shell"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatal("no Chrome or Chromium: the browser test must run in CI")
	}
	t.Skip("no Chrome or Chromium on this machine")
	return ""
}

// TestBrowser loads a page through the UI's real headers, htmx 4, hx-csp and
// app.js in headless Chrome, and swaps in a fragment as an attacker would
// shape one: the fragment's own nonce works, a forged hx-nonce leaves its
// element inert, and neither an inline script nor an inline handler runs;
// Trusted Types refuses HTML sinks; app.js sends the CSRF token (§7.4, T-05).
func TestBrowser(t *testing.T) {
	s := newServer(t)
	if err := s.pages.add("harness", `{{define "content"}}
<button id="load" hx-get="/ui/test/fragment" hx-target="#out" hx-swap="innerHTML" {{hxnonce}}>load</button>
<img id="injected" src="/ui/static/favicon.svg" alt="" onload="window.pwnedHandler = true">
<div id="out"></div><div id="ping"></div>{{end}}`); err != nil {
		t.Fatal(err)
	}
	var evil, csrfOK atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("/ui/static/", s.Handler())
	mux.Handle("GET /ui/test", s.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.page(w, r, 200, "harness", Page{Title: "harness", CSRF: "csrf-token-value"})
	})))
	mux.Handle("GET /ui/test/fragment", s.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<p id="loaded">loaded</p>
<button id="good" hx-post="/ui/test/ping" hx-target="#ping" hx-nonce="%s">good</button>
<button id="evil" hx-get="/ui/test/evil" hx-target="#ping" hx-trigger="load" hx-nonce="forged">evil</button>
<script>window.pwnedScript = true</script>`, Nonce(r.Context()))
	})))
	mux.Handle("POST /ui/test/ping", s.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") == "csrf-token-value" {
			csrfOK.Add(1)
		}
		_, _ = w.Write([]byte("pong"))
	})))
	mux.Handle("GET /ui/test/evil", s.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evil.Add(1)
		_, _ = w.Write([]byte("EVIL"))
	})))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome(t)), chromedp.IgnoreCertErrors)
	if os.Getenv("CI") != "" {
		opts = append(opts, chromedp.NoSandbox)
	}
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(alloc)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 60*time.Second)
	defer cancelTimeout()

	do := func(a chromedp.Action[chromedp.Void]) {
		t.Helper()
		if _, err := chromedp.Run(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	eval := func(expr string) bool {
		t.Helper()
		v, err := chromedp.Run(ctx, chromedp.Evaluate[bool](expr))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	do(chromedp.Navigate(srv.URL + "/ui/test"))
	do(chromedp.WaitVisible(chromedp.ID("load")))
	htmxLoaded := eval(`typeof htmx === "object"`)
	do(chromedp.Click(chromedp.ID("load")))
	do(chromedp.WaitVisible(chromedp.ID("loaded")))
	do(chromedp.Sleep(500 * time.Millisecond)) // the evil button's hx-trigger="load" would fire now
	goodWired := eval(`document.getElementById("good").hasAttribute("hx-post")`)
	evilWired := eval(`document.getElementById("evil").hasAttribute("hx-get")`)
	do(chromedp.Click(chromedp.ID("good")))
	do(chromedp.WaitVisible(chromedp.CSS("#ping:not(:empty)")))
	ping, err := chromedp.Run(ctx, chromedp.Text(chromedp.ID("ping")))
	if err != nil {
		t.Fatal(err)
	}
	do(chromedp.Click(chromedp.ID("evil")))
	do(chromedp.Sleep(300 * time.Millisecond))
	pwnedScript := eval(`window.pwnedScript === true`)
	pwnedHandler := eval(`window.pwnedHandler === true`)
	sink, err := chromedp.Run(ctx, chromedp.Evaluate[string](
		`(() => { try { document.getElementById("out").innerHTML = "<b>x</b>"; return "written" } catch (e) { return e.name } })()`))
	if err != nil {
		t.Fatal(err)
	}
	if !htmxLoaded {
		t.Error("htmx did not load under the CSP")
	}
	if !goodWired || ping != "pong" || csrfOK.Load() != 1 {
		t.Errorf("the fragment's own nonce: wired %v, ping %q, CSRF header seen %d times", goodWired, ping, csrfOK.Load())
	}
	if evilWired || evil.Load() != 0 {
		t.Errorf("a forged hx-nonce: attribute kept %v, requests %d", evilWired, evil.Load())
	}
	if pwnedScript || pwnedHandler {
		t.Errorf("inline code ran: script %v, handler %v", pwnedScript, pwnedHandler)
	}
	if sink != "TypeError" {
		t.Errorf("Trusted Types: innerHTML %s", sink)
	}
}
