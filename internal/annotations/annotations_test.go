package annotations

import (
	"strings"
	"testing"
	"unicode/utf8"
)

type in struct {
	Description string
	Annotations map[string]string
}

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
		b    in
		want string // a substring of the error, empty for none
	}{
		"empty":                 {in{}, ""},
		"description at limit":  {in{Description: strings.Repeat("é", 4096)}, ""},
		"description over":      {in{Description: strings.Repeat("é", 4097)}, "description"},
		"newline and tab":       {in{Description: "a\nb\tc"}, ""},
		"control character":     {in{Description: "a\x07b"}, "description"},
		"escape":                {in{Description: "a\x1b[31mb"}, "description"},
		"invalid UTF-8":         {in{Description: "a\xffb"}, "description"},
		"32 entries":            {in{Annotations: exactly32}, ""},
		"33 entries":            {in{Annotations: many}, "annotations"},
		"too big in total":      {in{Annotations: big}, "annotations"},
		"key at limit":          {in{Annotations: map[string]string{"a" + strings.Repeat("b", 62): "v"}}, ""},
		"key over":              {in{Annotations: map[string]string{"a" + strings.Repeat("b", 63): "v"}}, "key"},
		"empty key":             {in{Annotations: map[string]string{"": "v"}}, "key"},
		"key starts with a dot": {in{Annotations: map[string]string{".a": "v"}}, "key"},
		"key with a space":      {in{Annotations: map[string]string{"a b": "v"}}, "key"},
		"key with a slash":      {in{Annotations: map[string]string{"example.org/change-id": "v"}}, ""},
		"empty value":           {in{Annotations: map[string]string{"a": ""}}, ""},
		"value at limit":        {in{Annotations: map[string]string{"a": strings.Repeat("é", 256)}}, ""},
		"value over":            {in{Annotations: map[string]string{"a": strings.Repeat("é", 257)}}, "value"},
		"newline in a value":    {in{Annotations: map[string]string{"a": "x\ny"}}, "value"},
		"bad UTF-8 in a value":  {in{Annotations: map[string]string{"a": "\xff"}}, "value"},
	} {
		err := Check(tc.b.Description, tc.b.Annotations)
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
		err := Check(desc, map[string]string{key: value})
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
