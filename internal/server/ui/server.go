// Package ui serves the HTMX admin UI under /ui/ on the admin listener
// (§7.3, §7.4, §7.6): every response carries the security headers with a
// fresh nonce, and pages are rendered from web/templates.
package ui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/ratelimit"
	"github.com/dihedron/ligo/internal/theme"
	"github.com/dihedron/ligo/web"
	"github.com/jackc/pgx/v5/pgxpool"
)

// htmxConfig is the <meta name="htmx-config"> of every page (§7.4).
var htmxConfig = mustJSON(map[string]any{"extensions": "hx-csp", "mode": "same-origin", "noSwap": []any{204, 304, "5xx"},
	"defaultTimeout": 90000, "includeIndicatorCSS": false, "history": true, "implicitInheritance": false})

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Server is the admin UI.
type Server struct {
	Theme       *theme.Theme
	ThemeConfig config.Theme
	Logger      *slog.Logger

	// sessions (§7.3)
	DB       *pgxpool.Pool // the app pool
	LDAP     Directory
	Authz    *authz.Authorizer
	Listener config.AdminListener
	Logins   *ratelimit.Logins // shared with the admin API's Basic credentials

	pages *pages
}

// New parses the templates; a template that does not parse is a build
// error, caught by the tests.
func New(th *theme.Theme, cfg config.Theme, log *slog.Logger) (*Server, error) {
	p, err := parse()
	if err != nil {
		return nil, err
	}
	return &Server{Theme: th, ThemeConfig: cfg, Logger: log, pages: p}, nil
}

// Handler routes /ui/ behind the security headers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(web.FS, "static")
	files := http.StripPrefix("/ui/static/", http.FileServerFS(static))
	mux.HandleFunc("GET /ui/static/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || strings.HasSuffix(r.URL.Path, "/VERSIONS") {
			http.NotFound(w, r) // no directory listings
			return
		}
		files.ServeHTTP(w, r)
	})
	mux.Handle("GET /ui/theme/", s.Theme.Handler())
	mux.HandleFunc("GET /ui/login", s.loginPage)
	mux.HandleFunc("POST /ui/login", s.login)
	mux.Handle("/ui/", s.authed(s.routes()))
	return s.secure(mux)
}

// routes are the pages and actions of a signed-in user.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ui/{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ui/bindings", http.StatusSeeOther) })
	mux.HandleFunc("POST /ui/logout", s.logout)
	mux.HandleFunc("POST /ui/preferences/theme", s.preference)
	mux.HandleFunc("GET /ui/bindings", func(w http.ResponseWriter, r *http.Request) {
		s.page(w, r, http.StatusOK, "bindings", s.frame(r, "Bindings", "/ui/bindings"))
	})
	return mux
}

type nonceKey struct{}

// Nonce is the response's CSP nonce.
func Nonce(ctx context.Context) string {
	n, _ := ctx.Value(nonceKey{}).(string)
	return n
}

// policy is the §7.4 Content-Security-Policy for nonce n.
func policy(n string) string {
	return "default-src 'none'; script-src 'self' 'nonce-" + n + "'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types htmx"
}

// secure sets the §7.4 security headers on every /ui/ response, with a
// fresh nonce of 16 random bytes for each, page or fragment; the theme
// handler alone overrides Cache-Control (and CSP for SVG).
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		_, _ = rand.Read(b) // crypto/rand.Read never fails
		n := base64.StdEncoding.EncodeToString(b)
		h := w.Header()
		h.Set("Content-Security-Policy", policy(n))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cache-Control", "no-store")
		id := uuid.NewV7().String()
		h.Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(audit.WithRequestID(r.Context(), id), nonceKey{}, n)))
	})
}

// mode is the color mode of the request: the __Host-ligo_theme cookie if
// valid, else ui.theme.default_mode (§7.6).
func (s *Server) mode(r *http.Request) string {
	if c, err := r.Cookie("__Host-ligo_theme"); err == nil && slices.Contains(theme.Modes, c.Value) {
		return c.Value
	}
	return s.ThemeConfig.DefaultMode
}
