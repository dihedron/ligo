package theme

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
)

// Tokens are the color tokens a theme may set in ui.theme.colors, without
// the --color- prefix (§7.6).
var Tokens = []string{"bg", "surface", "border", "text", "text-muted", "primary", "primary-contrast", "success", "success-contrast",
	"warning", "warning-contrast", "danger", "danger-contrast", "focus"}

// Modes are ui.theme.default_mode's values.
var Modes = []string{"system", "light", "dark"}

// Files are the settings of ui.theme that name files (§7.6).
type Files struct {
	Directory                           string // conventional files; default /etc/ligo/theme
	CSS, Logo, LogoDark, Favicon, Fonts string // explicit paths, which win
	Colors                              map[string]map[string]string
}

// Asset is a theme file, or the generated tokens.css, served from memory.
type Asset struct {
	Path        string // "" for tokens.css
	ContentType string
	Data        []byte
	SHA256      string
}

// Theme is the loaded theme; nil assets fall back to the built-in ones.
type Theme struct {
	Tokens, CSS, Logo, LogoDark, Favicon *Asset
	Fonts                                map[string]*Asset // by file name
}

// Options are the checks' parameters.
type Options struct {
	OwnerUID uint32 // 0 (root) in production
	Logger   *slog.Logger
}

const (
	maxCSS   = 256 << 10
	maxImage = 512 << 10
	maxFont  = 1 << 20
	maxFonts = 16
)

var types = map[string]string{".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp",
	".ico": "image/x-icon", ".woff2": "font/woff2"}

// remote finds what the browser would fetch from elsewhere: @import and
// url() with a scheme or a protocol-relative address.
var remote = regexp.MustCompile(`(?i)@import|url\(\s*['"]?\s*([a-z][a-z0-9+.-]*:|//)`)

// Load reads and checks the theme once, at startup (§7.6, §8.2 rule 15):
// explicit files must exist; conventional ones are optional; every file
// has an allowed extension, is within its size limit, matches its type by
// content, is owned by OwnerUID and is not writable by group or others.
func Load(f Files, opts Options) (*Theme, error) {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if f.Directory == "" {
		f.Directory = "/etc/ligo/theme"
	}
	t := &Theme{Fonts: map[string]*Asset{}}
	var errs []error
	load := func(explicit string, conventional string, exts []string, limit int) *Asset {
		path := explicit
		if path == "" {
			var found []string
			for _, ext := range exts {
				if p := filepath.Join(f.Directory, conventional+ext); exists(p) {
					found = append(found, p)
				}
			}
			if len(found) == 0 {
				return nil
			}
			if len(found) > 1 {
				log.Warn("theme: several files for one element, the first is used", "used", found[0], "ignored", found[1:])
			}
			path = found[0]
		} else if !slices.Contains(exts, filepath.Ext(path)) {
			errs = append(errs, fmt.Errorf("rule 15: %s: extension not one of %v", path, exts))
			return nil
		}
		a, err := read(path, limit, opts.OwnerUID)
		if err != nil {
			errs = append(errs, err)
		}
		return a
	}
	image := []string{".svg", ".png", ".webp"}
	t.CSS = load(f.CSS, "theme", []string{".css"}, maxCSS)
	t.Logo = load(f.Logo, "logo", image, maxImage)
	t.LogoDark = load(f.LogoDark, "logo-dark", image, maxImage)
	t.Favicon = load(f.Favicon, "favicon", []string{".svg", ".png", ".ico"}, maxImage)
	if t.CSS != nil {
		for _, m := range remote.FindAllString(string(t.CSS.Data), -1) {
			log.Warn("theme: theme.css references a remote resource, which the CSP blocks", "file", t.CSS.Path, "reference", m)
		}
	}

	fonts := f.Fonts
	if fonts == "" {
		fonts = filepath.Join(f.Directory, "fonts")
	}
	names, err := filepath.Glob(filepath.Join(fonts, "*.woff2"))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("rule 15: fonts: %w", err))
	case f.Fonts != "" && !exists(f.Fonts):
		errs = append(errs, fmt.Errorf("rule 15: fonts_dir %s does not exist", f.Fonts))
	case len(names) > maxFonts:
		errs = append(errs, fmt.Errorf("rule 15: %s: %d fonts, at most %d", fonts, len(names), maxFonts))
	default:
		for _, p := range names {
			a, err := read(p, maxFont, opts.OwnerUID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			t.Fonts[filepath.Base(p)] = a
		}
	}

	if tokens := tokensCSS(f.Colors); tokens != nil {
		t.Tokens = &Asset{ContentType: types[".css"], Data: tokens, SHA256: sum(tokens)}
		warnContrast(log, f.Colors)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return t, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// read loads one file through its descriptor, so the checks and the data
// are of the same file.
func read(path string, limit int, owner uint32) (*Asset, error) {
	ext := filepath.Ext(path)
	file, err := os.Open(path) //nolint:gosec // the path comes from the operator's configuration
	if err != nil {
		return nil, fmt.Errorf("rule 15: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("rule 15: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("rule 15: %s: not a regular file", path)
	}
	if err := ownership(path, info, owner); err != nil {
		return nil, err
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("rule 15: %s: %d bytes, at most %d", path, info.Size(), limit)
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("rule 15: %s: %w", path, err)
	}
	if !matches(ext, data) {
		return nil, fmt.Errorf("rule 15: %s: content does not match %s", path, types[ext])
	}
	return &Asset{Path: path, ContentType: types[ext], Data: data, SHA256: sum(data)}, nil
}

// ownership: owned by owner, and not writable by group or others, so the
// ligo user cannot change the UI's appearance (T-22).
func ownership(path string, info fs.FileInfo, owner uint32) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("rule 15: %s: no ownership information", path)
	}
	if st.Uid != owner {
		return fmt.Errorf("rule 15: %s: owned by uid %d, want %d", path, st.Uid, owner)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("rule 15: %s: writable by group or others (%v)", path, info.Mode().Perm())
	}
	return nil
}

// matches sniffs the content of images and fonts.
func matches(ext string, data []byte) bool {
	switch ext {
	case ".png":
		return bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n"))
	case ".webp":
		return len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP"
	case ".ico":
		return bytes.HasPrefix(data, []byte{0, 0, 1, 0})
	case ".svg":
		head := strings.ToLower(string(data[:min(len(data), 4096)]))
		return strings.Contains(head, "<svg")
	case ".woff2":
		return bytes.HasPrefix(data, []byte("wOF2"))
	}
	return true // CSS is text, not sniffed
}

func sum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// tokensCSS is /ui/theme/tokens.css from ui.theme.colors: the light values
// on :root, the dark ones under both dark-mode selectors (§7.6); nil when
// no color is set.
func tokensCSS(colors map[string]map[string]string) []byte {
	if len(colors["light"]) == 0 && len(colors["dark"]) == 0 {
		return nil
	}
	decls := func(m map[string]string, indent string) string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s--color-%s: %s;\n", indent, k, m[k])
		}
		return b.String()
	}
	var b strings.Builder
	b.WriteString("/* generated by ligo from ui.theme.colors (§7.6) */\n")
	if light := colors["light"]; len(light) > 0 {
		fmt.Fprintf(&b, ":root {\n%s}\n", decls(light, "  "))
	}
	if dark := colors["dark"]; len(dark) > 0 {
		fmt.Fprintf(&b, "@media (prefers-color-scheme: dark) {\n  :root:not([data-theme=\"light\"]) {\n%s  }\n}\n", decls(dark, "    "))
		fmt.Fprintf(&b, ":root[data-theme=\"dark\"] {\n%s}\n", decls(dark, "  "))
	}
	return []byte(b.String())
}

// warnContrast logs every text token below MinContrast on its background
// in a mode where ui.theme.colors sets either of them, over the built-in
// palette of that mode (§7.6 contrast check).
func warnContrast(log *slog.Logger, colors map[string]map[string]string) {
	builtin, err := Builtin()
	if err != nil {
		log.Warn("theme: the built-in palettes cannot be read for the contrast check", "error", err)
		return
	}
	for mode, set := range colors {
		effective := map[string]string{}
		for k, v := range builtin[mode] {
			effective[k] = v
		}
		for k, v := range set {
			effective[k] = v
		}
		for _, p := range Pairs {
			_, a := set[p[0]]
			_, b := set[p[1]]
			if !a && !b {
				continue
			}
			if ratio, err := Contrast(effective[p[0]], effective[p[1]]); err == nil && ratio < MinContrast {
				log.Warn("theme: contrast below WCAG AA", "mode", mode, "text", "--color-"+p[0], "background", "--color-"+p[1],
					"ratio", fmt.Sprintf("%.2f", ratio))
			}
		}
	}
}

// Hashes are the SHA-256 values of the theme in use, for CONFIG_LOADED
// (§7.6, §8.2 step 2).
func (t *Theme) Hashes() map[string]string {
	out := map[string]string{}
	add := func(name string, a *Asset) {
		if a != nil {
			out[name] = a.SHA256
		}
	}
	add("tokens.css", t.Tokens)
	add("theme.css", t.CSS)
	add("logo", t.Logo)
	add("logo-dark", t.LogoDark)
	add("favicon", t.Favicon)
	for name, a := range t.Fonts {
		add("fonts/"+name, a)
	}
	return out
}
