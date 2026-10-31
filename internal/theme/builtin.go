package theme

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"regexp"

	"github.com/dihedron/ligo/web"
)

var (
	block = regexp.MustCompile(`(?s)(:root(?:\[data-theme="dark"\])?|:root:not\(\[data-theme="light"\]\))\s*\{([^}]*)\}`)
	token = regexp.MustCompile(`--color-([a-z-]+):\s*(#[0-9a-fA-F]+);`)
)

// Builtin reads the built-in palettes from styles.css, by mode ("light",
// "dark"); the two dark-mode blocks must agree (§7.6).
func Builtin() (map[string]map[string]string, error) {
	css, err := fs.ReadFile(web.FS, "static/styles.css")
	if err != nil {
		return nil, err
	}
	palettes := map[string]map[string]string{}
	for _, m := range block.FindAllStringSubmatch(string(css), -1) {
		p := map[string]string{}
		for _, t := range token.FindAllStringSubmatch(m[2], -1) {
			p[t[1]] = t[2]
		}
		if len(p) > 0 {
			palettes[m[1]] = p
		}
	}
	light, dark, system := palettes[":root"], palettes[`:root[data-theme="dark"]`], palettes[`:root:not([data-theme="light"])`]
	if light == nil || dark == nil {
		return nil, errors.New("theme: styles.css lacks the light or the dark palette")
	}
	if !maps.Equal(dark, system) {
		return nil, fmt.Errorf("theme: styles.css's two dark palettes differ")
	}
	return map[string]map[string]string{"light": light, "dark": dark}, nil
}
