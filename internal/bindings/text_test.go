package bindings

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// BM-1: the limits of .specs/ligo-binding-annotations.md §3.2, at the edge and one over.
func TestCheckText(t *testing.T) {
	many := map[string]string{}
	for i := 0; i < 33; i++ {
		many["k"+strings.Repeat("x", i)] = "v"
	}
	exactly32 := map[string]string{}
	for i := 0; i < 32; i++ {
		exactly32["k"+strings.Repeat("x", i)] = "v"
	}
	big := map[string]string{} // 32 entries of 63 + 256 bytes is 10 KiB
	for i := 0; i < 32; i++ {
		big[strings.Repeat(string(rune('a'+i%26)), 62)+string(rune('0'+i/26))] = strings.Repeat("v", 256)
	}
	for name, tc := range map[string]struct {
		b    Binding
		want string // a substring of the error, empty for none
	}{
		"empty":                 {Binding{}, ""},
		"description at limit":  {Binding{Description: strings.Repeat("é", 4096)}, ""},
		"description over":      {Binding{Description: strings.Repeat("é", 4097)}, "description"},
		"newline and tab":       {Binding{Description: "a\nb\tc"}, ""},
		"control character":     {Binding{Description: "a\x07b"}, "description"},
		"escape":                {Binding{Description: "a\x1b[31mb"}, "description"},
		"invalid UTF-8":         {Binding{Description: "a\xffb"}, "description"},
		"32 entries":            {Binding{Annotations: exactly32}, ""},
		"33 entries":            {Binding{Annotations: many}, "annotations"},
		"too big in total":      {Binding{Annotations: big}, "annotations"},
		"key at limit":          {Binding{Annotations: map[string]string{"a" + strings.Repeat("b", 62): "v"}}, ""},
		"key over":              {Binding{Annotations: map[string]string{"a" + strings.Repeat("b", 63): "v"}}, "key"},
		"empty key":             {Binding{Annotations: map[string]string{"": "v"}}, "key"},
		"key starts with a dot": {Binding{Annotations: map[string]string{".a": "v"}}, "key"},
		"key with a space":      {Binding{Annotations: map[string]string{"a b": "v"}}, "key"},
		"key with a slash":      {Binding{Annotations: map[string]string{"example.org/change-id": "v"}}, ""},
		"empty value":           {Binding{Annotations: map[string]string{"a": ""}}, ""},
		"value at limit":        {Binding{Annotations: map[string]string{"a": strings.Repeat("é", 256)}}, ""},
		"value over":            {Binding{Annotations: map[string]string{"a": strings.Repeat("é", 257)}}, "value"},
		"newline in a value":    {Binding{Annotations: map[string]string{"a": "x\ny"}}, "value"},
		"bad UTF-8 in a value":  {Binding{Annotations: map[string]string{"a": "\xff"}}, "value"},
	} {
		err := checkText(&tc.b)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want an error naming %q", name, err, tc.want)
		}
	}
}

// BM-10: the checker never panics, and accepts only what the rules say.
func FuzzCheckText(f *testing.F) {
	f.Add("a description", "key", "value")
	f.Add("\x00", "", "\xff")
	f.Fuzz(func(t *testing.T, desc, key, value string) {
		err := checkText(&Binding{Description: desc, Annotations: map[string]string{key: value}})
		if err != nil {
			return
		}
		if !utf8.ValidString(desc) || utf8.RuneCountInString(desc) > 4096 || len(key) == 0 || len(key) > 63 ||
			!utf8.ValidString(value) || utf8.RuneCountInString(value) > 256 {
			t.Fatalf("accepted %q %q %q", desc, key, value)
		}
		for _, r := range desc + value {
			if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
				t.Fatalf("accepted a control character in %q %q", desc, value)
			}
		}
	})
}
