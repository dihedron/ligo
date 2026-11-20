// Package annotations checks the description and the annotations that bindings,
// sources and targets carry (.specs/ligo-binding-annotations.md §3.2,
// .specs/ligo-resource-annotations.md §2).
package annotations

import (
	"fmt"
	"unicode/utf8"
)

// Limits of a description and of annotations.
const (
	maxDescription      = 4096 // runes
	maxAnnotations      = 32   // entries
	maxAnnotationsBytes = 8192 // keys and values together
	maxKey              = 63   // characters
	maxValue            = 256  // runes
)

// Check validates a description and a map of annotations; the error names the field.
func Check(description string, annotations map[string]string) error {
	if err := text("description", description, maxDescription, true); err != nil {
		return err
	}
	if len(annotations) > maxAnnotations {
		return fmt.Errorf("annotations has %d entries, the limit is %d", len(annotations), maxAnnotations)
	}
	total := 0
	for k, v := range annotations {
		if !validKey(k) {
			return fmt.Errorf("annotations key %q is not 1 to %d characters of [A-Za-z0-9._/-] starting with a letter or a digit", k, maxKey)
		}
		if err := text(fmt.Sprintf("annotations value of %q", k), v, maxValue, false); err != nil {
			return err
		}
		total += len(k) + len(v)
	}
	if total > maxAnnotationsBytes {
		return fmt.Errorf("annotations is %d bytes, the limit is %d", total, maxAnnotationsBytes)
	}
	return nil
}

// text checks UTF-8, the length in runes and control characters; newline
// and tab are allowed in a multi-line text only.
func text(name, s string, max int, multiline bool) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if n := utf8.RuneCountInString(s); n > max {
		return fmt.Errorf("%s has %d characters, the limit is %d", name, n, max)
	}
	for _, r := range s {
		if (r < 0x20 && (!multiline || r != '\n' && r != '\t')) || r == 0x7f {
			return fmt.Errorf("%s has a control character", name)
		}
	}
	return nil
}

func validKey(k string) bool {
	if k == "" || len(k) > maxKey {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || c != '.' && c != '_' && c != '/' && c != '-') {
			return false
		}
	}
	return true
}
