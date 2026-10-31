package web_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/theme"
	"github.com/dihedron/ligo/web"
)

// TestVendored: every vendored file has the SHA-256 that static/VERSIONS
// records, so an upgrade is a reviewed change of both (§7.4).
func TestVendored(t *testing.T) {
	versions, err := web.FS.Open("static/VERSIONS")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = versions.Close() }()
	n := 0
	for sc := bufio.NewScanner(versions); sc.Scan(); {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 4 {
			t.Fatalf("VERSIONS: %q is not name version path sha256", line)
		}
		data, err := fs.ReadFile(web.FS, "static/"+f[2])
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != f[3] {
			t.Errorf("%s: SHA-256 differs from VERSIONS", f[2])
		}
		n++
	}
	if n != 2 {
		t.Errorf("VERSIONS lists %d files, want htmx.min.js and ext/hx-csp.min.js", n)
	}
}

// TestPalettes: the built-in light and dark palettes meet WCAG 2.1 AA for
// every text token on its background (§7.6).
func TestPalettes(t *testing.T) {
	palettes, err := theme.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for mode, p := range palettes {
		for _, pair := range append([][2]string{{"text-muted", "bg"}, {"text-muted", "surface"}}, theme.Pairs...) {
			ratio, err := theme.Contrast(p[pair[0]], p[pair[1]])
			if err != nil || ratio < theme.MinContrast {
				t.Errorf("%s: --color-%s on --color-%s: %.2f %v", mode, pair[0], pair[1], ratio, err)
			}
		}
		for _, tk := range theme.Tokens {
			if !theme.ValidColor(p[tk]) {
				t.Errorf("%s: --color-%s is missing", mode, tk)
			}
		}
	}
}
