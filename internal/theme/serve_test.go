package theme

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// TestHandler: theme assets are public and cacheable with their SHA-256 as
// ETag; SVG gets the sandbox CSP; unknown or absent assets are 404.
func TestHandler(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "logo.svg"), svg)
	write(t, filepath.Join(dir, "favicon.png"), png)
	write(t, filepath.Join(dir, "fonts", "brand.woff2"), woff2)
	th, err := Load(Files{Directory: dir, Colors: map[string]map[string]string{"light": {"primary": "#1f4e8c"}}}, me())
	if err != nil {
		t.Fatal(err)
	}
	h := th.Handler()
	get := func(path, etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Security-Policy", "default-src 'none'") // the UI's, set before
		rec.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(rec, req)
		return rec
	}
	logo := get("/ui/theme/logo", "")
	if logo.Code != 200 || logo.Body.String() != string(svg) || logo.Header().Get("Content-Type") != "image/svg+xml" ||
		logo.Header().Get("Content-Security-Policy") != svgPolicy || logo.Header().Get("Cache-Control") != "public, max-age=3600" ||
		logo.Header().Get("ETag") != `"`+sum(svg)+`"` || logo.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("logo: %d %v", logo.Code, logo.Header())
	}
	if again := get("/ui/theme/logo", logo.Header().Get("ETag")); again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Errorf("If-None-Match: %d", again.Code)
	}
	if fav := get("/ui/theme/favicon", ""); fav.Code != 200 || fav.Header().Get("Content-Security-Policy") != "default-src 'none'" {
		t.Errorf("favicon keeps the UI's CSP: %d %v", fav.Code, fav.Header())
	}
	for path, code := range map[string]int{"/ui/theme/tokens.css": 200, "/ui/theme/fonts/brand.woff2": 200, "/ui/theme/theme.css": 404,
		"/ui/theme/logo-dark": 404, "/ui/theme/fonts/../logo": 404, "/ui/theme/other": 404} {
		if rec := get(path, ""); rec.Code != code {
			t.Errorf("%s: %d, want %d", path, rec.Code, code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/ui/theme/logo", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}
