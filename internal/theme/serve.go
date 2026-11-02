package theme

import (
	"net/http"
	"strings"
)

// svgPolicy replaces the UI's CSP for SVG responses, so a script in a logo
// never runs, even when the logo is opened directly (§7.6).
const svgPolicy = "sandbox; default-src 'none'; style-src 'unsafe-inline'"

// Handler serves /ui/theme/{tokens.css,theme.css,logo,logo-dark,favicon}
// and /ui/theme/fonts/{name}.woff2 from memory, public and cacheable, with
// the file's SHA-256 as ETag (§7.6). It runs after the UI's security
// headers, and overrides their Cache-Control (and CSP for SVG).
func (t *Theme) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a := t.asset(strings.TrimPrefix(r.URL.Path, "/ui/theme/"))
		if a == nil {
			http.NotFound(w, r)
			return
		}
		etag := `"` + a.SHA256 + `"`
		h := w.Header()
		h.Set("Content-Type", a.ContentType)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "public, max-age=3600")
		h.Set("ETag", etag)
		if a.ContentType == types[".svg"] {
			h.Set("Content-Security-Policy", svgPolicy)
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(a.Data) //nolint:gosec // G705: operator-provided theme files, typed by extension and sniffed at startup; SVG under a sandbox CSP
	})
}

func (t *Theme) asset(name string) *Asset {
	switch name {
	case "tokens.css":
		return t.Tokens
	case "theme.css":
		return t.CSS
	case "logo":
		return t.Logo
	case "logo-dark":
		return t.LogoDark
	case "favicon":
		return t.Favicon
	}
	if font, ok := strings.CutPrefix(name, "fonts/"); ok && !strings.Contains(font, "/") {
		return t.Fonts[font]
	}
	return nil
}
