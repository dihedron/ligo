package ui

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/dihedron/ligo/internal/theme"
	"github.com/dihedron/ligo/web"
)

// pages are the parsed templates: each page with the layout, and the
// fragments alone (no layout, no script).
type pages struct {
	page     map[string]*template.Template // by name: pages/<name>.html
	fragment *template.Template            // every fragments/*.html
}

// funcs are the templates' functions; nonce and hxnonce are bound to the
// response's nonce at each render (placeholders here).
func funcs() template.FuncMap {
	return template.FuncMap{
		"nonce":      func() string { return "" },
		"hxnonce":    func() template.HTMLAttr { return "" },
		"htmxConfig": func() string { return htmxConfig },
		"modes":      func() []string { return theme.Modes },
		"when":       when,
		"pretty":     pretty,
		"badge":      badge,
		"list":       func(v ...string) []string { return v },
	}
}

// when is a time in UTC, to the minute; "" for none.
func when(v any) string {
	switch t := v.(type) {
	case time.Time:
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	case *time.Time:
		if t == nil {
			return ""
		}
		return when(*t)
	}
	return ""
}

// pretty indents a JSON value for a <pre>; html/template escapes it.
func pretty(v any) string {
	var data []byte
	switch x := v.(type) {
	case json.RawMessage:
		data = x
	case []byte:
		data = x
	default:
		var err error
		if data, err = json.Marshal(v); err != nil {
			return ""
		}
	}
	var out bytes.Buffer
	if err := json.Indent(&out, data, "", "  "); err != nil {
		return string(data)
	}
	return out.String()
}

// badge is a phase's or status's badge class (§7.6 tokens).
func badge(state string) string {
	switch state {
	case "ACTIVE", "APPLIED", "APPROVED":
		return "badge badge-success"
	case "FAILED", "DELETE_FAILED", "FAILED_TO_APPLY", "DECLINED", "REVERTED":
		return "badge badge-danger"
	case "PROVISIONING", "DELETING", "PENDING":
		return "badge badge-warning"
	}
	return "badge"
}

// bound returns funcs that give nonce n: templates write hx-nonce through
// hxnonce only, never by hand (§7.4).
func bound(n string) template.FuncMap {
	return template.FuncMap{
		"nonce": func() string { return n },
		// G203: n is our own base64 nonce, escaped; the attribute name is fixed
		"hxnonce": func() template.HTMLAttr { return template.HTMLAttr(`hx-nonce="` + template.HTMLEscapeString(n) + `"`) }, //nolint:gosec
	}
}

func parse() (*pages, error) {
	p := &pages{page: map[string]*template.Template{}}
	fragments, err := fs.Glob(web.FS, "templates/fragments/*.html")
	if err != nil {
		return nil, err
	}
	base := template.New("ui").Funcs(funcs())
	if len(fragments) > 0 {
		if base, err = base.ParseFS(web.FS, fragments...); err != nil {
			return nil, err
		}
	}
	p.fragment = base
	names, err := fs.Glob(web.FS, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		t, err := template.Must(base.Clone()).ParseFS(web.FS, "templates/layout.html", name)
		if err != nil {
			return nil, err
		}
		p.page[strings.TrimSuffix(path.Base(name), ".html")] = t
	}
	return p, nil
}

// add parses an extra page from src, with the layout (tests).
func (p *pages) add(name, src string) error {
	t, err := template.Must(p.fragment.Clone()).ParseFS(web.FS, "templates/layout.html")
	if err != nil {
		return err
	}
	if _, err := t.New(name).Parse(src); err != nil {
		return err
	}
	p.page[name] = t
	return nil
}

// Assets says which theme files exist, for the layout.
type Assets struct{ Tokens, CSS, Logo, LogoDark, Favicon bool }

// NavItem is an entry of the main navigation.
type NavItem struct {
	Path, Label string
	Current     bool
}

// Maintenance is the maintenance banner's data (§10.3).
type Maintenance struct{ Reason string }

// OpenBreakGlass is an entry of the break-glass banner (ADR-12).
type OpenBreakGlass struct{ Name, ExpiresIn string }

// Page is the layout's data around a page's content.
type Page struct {
	Title       string
	Product     string
	ThemeMode   string // "light" or "dark" for an explicit choice, "" for system
	ThemeChoice string // the selected mode, for the switch
	Assets      Assets
	CSRF        string
	User        string
	Nav         []NavItem
	Maintenance *Maintenance
	BreakGlass  []OpenBreakGlass
	Content     any
}

// page renders the page name for r with the response's nonce.
func (s *Server) page(w http.ResponseWriter, r *http.Request, status int, name string, p Page) {
	t, ok := s.pages.page[name]
	if !ok {
		s.Logger.Error("ui: no such page", "page", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p.Product = s.ThemeConfig.ProductName
	p.ThemeChoice = s.mode(r)
	if p.ThemeChoice != "system" {
		p.ThemeMode = p.ThemeChoice
	}
	if th := s.Theme; th != nil {
		p.Assets = Assets{Tokens: th.Tokens != nil, CSS: th.CSS != nil, Logo: th.Logo != nil, LogoDark: th.LogoDark != nil, Favicon: th.Favicon != nil}
	}
	s.execute(w, r, status, template.Must(t.Clone()), "layout", p)
}

// fragment renders the fragment name for r with the response's nonce.
func (s *Server) fragment(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	s.execute(w, r, status, template.Must(s.pages.fragment.Clone()), name, data)
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request, status int, t *template.Template, name string, data any) {
	var buf bytes.Buffer
	if err := t.Funcs(bound(Nonce(r.Context()))).ExecuteTemplate(&buf, name, data); err != nil {
		s.Logger.Error("ui: render", "template", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// Alert is the alert fragment's data.
type Alert struct {
	Message   string
	Warning   bool
	RequestID string
}

// alert answers status with an alert fragment: into the form's error
// container for 409 and 422 (the form's hx-status), else retargeted to the
// page's error container (§7.4).
func (s *Server) alert(w http.ResponseWriter, r *http.Request, status int, message string) {
	if status != http.StatusConflict && status != http.StatusUnprocessableEntity {
		w.Header().Set("HX-Retarget", "#page-errors")
		w.Header().Set("HX-Reswap", "innerHTML")
	}
	s.fragment(w, r, status, "alert", Alert{Message: message, RequestID: w.Header().Get("X-Request-Id")})
}

// redirect answers a full-page navigation after a mutation: 200 with
// HX-Redirect, never a 3xx (§7.4).
func redirect(w http.ResponseWriter, target string) {
	w.Header().Set("HX-Redirect", target)
	w.WriteHeader(http.StatusOK)
}
