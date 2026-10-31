package web

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/theme"
)

// TestVendored: every vendored file has the SHA-256 that static/VERSIONS
// records, so an upgrade is a reviewed change of both (§7.4).
func TestVendored(t *testing.T) {
	versions, err := FS.Open("static/VERSIONS")
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
		data, err := fs.ReadFile(FS, "static/"+f[2])
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

var (
	block = regexp.MustCompile(`(?s)(:root(?:\[data-theme="dark"\])?|:root:not\(\[data-theme="light"\]\))\s*\{([^}]*)\}`)
	token = regexp.MustCompile(`--color-([a-z-]+):\s*(#[0-9a-fA-F]+);`)
)

// TestPalettes: the built-in light and dark palettes meet WCAG 2.1 AA for
// every text token on its background (§7.6), and both dark blocks agree.
func TestPalettes(t *testing.T) {
	css, err := fs.ReadFile(FS, "static/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	palettes := map[string]map[string]string{}
	for _, m := range block.FindAllStringSubmatch(string(css), -1) {
		p := map[string]string{}
		for _, tk := range token.FindAllStringSubmatch(m[2], -1) {
			p[tk[1]] = tk[2]
		}
		if len(p) > 0 {
			palettes[m[1]] = p
		}
	}
	light, dark, system := palettes[":root"], palettes[`:root[data-theme="dark"]`], palettes[`:root:not([data-theme="light"])`]
	if light == nil || dark == nil || fmt.Sprint(dark) != fmt.Sprint(system) {
		t.Fatalf("palettes: light %v, dark %v, system dark %v", light, dark, system)
	}
	for name, p := range map[string]map[string]string{"light": light, "dark": dark} {
		pairs := append([][2]string{{"text-muted", "bg"}, {"text-muted", "surface"}}, theme.Pairs...)
		for _, pair := range pairs {
			ratio, err := theme.Contrast(p[pair[0]], p[pair[1]])
			if err != nil || ratio < theme.MinContrast {
				t.Errorf("%s: --color-%s on --color-%s: %.2f %v", name, pair[0], pair[1], ratio, err)
			}
		}
	}
}
