package metrics

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestNormativeNames: every metric §10.1 names is declared, here or (the
// resolution cache's two) by ligo serve, and nothing else carries ligo_.
func TestNormativeNames(t *testing.T) {
	spec, err := os.ReadFile("../../.specs/ligo_specification.md")
	if err != nil {
		t.Fatal(err)
	}
	section := string(spec)
	section = section[strings.Index(section, "### 10.1 Observability"):strings.Index(section, "### 10.2 High availability")]
	want := map[string]bool{}
	for _, m := range regexp.MustCompile("`(ligo_[a-z_]+)").FindAllStringSubmatch(section, -1) {
		want[m[1]] = true
	}
	if len(want) < 25 {
		t.Fatalf("only %d names found in §10.1", len(want))
	}
	got := map[string]bool{"ligo_resolution_cache_age_seconds": true, "ligo_resolution_invalid_regex_total": true} // ligo serve's, per run
	ch := make(chan *prometheus.Desc, 256)
	go func() {
		Registry.Describe(ch)
		(&DB{}).Describe(ch)
		close(ch)
	}()
	name := regexp.MustCompile(`fqName: "([^"]+)"`)
	for d := range ch {
		if m := name.FindStringSubmatch(d.String()); m != nil && strings.HasPrefix(m[1], "ligo_") {
			got[m[1]] = true
		}
	}
	for n := range want {
		if !got[n] {
			t.Errorf("%s (§10.1) is not declared", n)
		}
	}
	for n := range got {
		if !want[n] {
			t.Errorf("%s is not in §10.1", n)
		}
	}
}
