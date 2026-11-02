// Package theme is the admin UI's appearance (§7.6): design tokens, their
// contrast, and the operator's theme files.
package theme

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
)

// Pairs are the text tokens checked against their backgrounds (§7.6
// contrast check), without the --color- prefix.
var Pairs = [][2]string{
	{"text", "bg"}, {"text", "surface"},
	{"primary-contrast", "primary"}, {"success-contrast", "success"},
	{"warning-contrast", "warning"}, {"danger-contrast", "danger"},
}

// MinContrast is WCAG 2.1 AA for normal text.
const MinContrast = 4.5

var hexColor = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)

// ValidColor reports whether s is a CSS hex color: #rgb, #rrggbb or
// #rrggbbaa (§8.2 rule 15).
func ValidColor(s string) bool { return hexColor.MatchString(s) }

// luminance is the WCAG relative luminance of a hex color; an alpha
// channel is ignored.
func luminance(s string) (float64, error) {
	if !ValidColor(s) {
		return 0, fmt.Errorf("theme: %q is not a hex color", s)
	}
	h := s[1:]
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	var l [3]float64
	for i := range 3 {
		v, _ := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		c := float64(v) / 255
		if c <= 0.04045 {
			l[i] = c / 12.92
		} else {
			l[i] = math.Pow((c+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*l[0] + 0.7152*l[1] + 0.0722*l[2], nil
}

// Contrast is the WCAG contrast ratio of two hex colors, from 1 to 21.
func Contrast(a, b string) (float64, error) {
	la, err := luminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := luminance(b)
	if err != nil {
		return 0, err
	}
	return (max(la, lb) + 0.05) / (min(la, lb) + 0.05), nil
}
