package governance

import (
	"errors"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/regexpolicy"
)

// c is C in the Appendix D.2 vectors.
const c = `^spiffe://cloud\.internal/acct/fin-01/tenant/`

const (
	tenancyRegex    = `^/acct/([a-z0-9-]+)/tenant/([a-z0-9-]+)/`
	tenancyTemplate = `cloud/${1}/${2}`
)

// TestAppendixD2Extractors runs the extractor configuration vectors of D.2.
func TestAppendixD2Extractors(t *testing.T) {
	for _, v := range []struct {
		pathRegex, template string
		accept              bool
	}{
		{tenancyRegex, tenancyTemplate, true},
		{`^/ns/([a-z0-9-]+)/`, `k8s/${1}`, true},
		{`^/ns/([^/]+)/`, `k8s/${1}`, true},
		{`^/acct/(.+)/`, `c/${1}`, false},
		{`^/acct/([a-z/]+)/`, `c/${1}`, false},
		{`^/acct/([a-z0-9-]+)`, `c/${1}`, false},
		{`^/acct/([a-z0-9-]*)/`, `c/${1}`, false},
		{`/acct/([a-z0-9-]+)/`, `c/${1}`, false},
		{`^/acct/(?i:([a-z]+))/`, `c/${1}`, false},
		{`^/acct/(?:x|y)/([a-z]+)/`, `c/${1}`, false},
		{`^/acct/([a-z]+)/`, `c/${2}`, false},
		{`^/acct/([a-z]+)/`, `c/$1`, false},
		{`^/acct/[a-z]+/`, `c`, false},
	} {
		e, err := NewPathTemplateExtractor(v.pathRegex, v.template)
		if v.accept && (err != nil || e == nil) {
			t.Errorf("(%q, %q): rejected (%v), want accepted", v.pathRegex, v.template, err)
		}
		if !v.accept && err == nil {
			t.Errorf("(%q, %q): accepted, want rejected", v.pathRegex, v.template)
		}
		if err != nil {
			t.Logf("(%q, %q): %v", v.pathRegex, v.template, err)
		}
	}
}

// TestAppendixD2Extraction runs the extraction vectors of D.2; each regex
// also passes the Appendix A validator, as D.2 states.
func TestAppendixD2Extraction(t *testing.T) {
	e, err := NewPathTemplateExtractor(tenancyRegex, tenancyTemplate)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ regex, scope string }{
		{c + `payments/sa/worker-[0-9]+$`, "cloud/fin-01/payments"},
		{c + `payments/sa/(?:api|web)-[0-9]+$`, "cloud/fin-01/payments"},
		{c + `payments/sa/x$`, "cloud/fin-01/payments"},
		{c + `(payments|hr)/sa/x$`, ""},
		{c + `pay(?:ments|roll)/sa/x$`, ""},
		{c + `payments$`, ""},
		{c + `[a-z]+/sa/x$`, ""},
		{c + `-pay/sa/x$`, ""},
		{`^spiffe://cloud\.internal/acct/Fin-01/tenant/payments/sa/x$`, ""},
	} {
		if _, err := regexpolicy.ValidateSVIDRegex(v.regex, "cloud.internal", policyD2); err != nil {
			t.Errorf("%q does not pass Appendix A: %v", v.regex, err)
		}
		checkScope(t, e, v.regex, "cloud.internal", v.scope)
	}
}

// TestAC45 is acceptance scenario AC-45: a regex covering two tenancies
// has no scope.
func TestAC45(t *testing.T) {
	e, err := NewPathTemplateExtractor(tenancyRegex, tenancyTemplate)
	if err != nil {
		t.Fatal(err)
	}
	checkScope(t, e, c+`(payments|hr)/sa/x$`, "cloud.internal", "")
	checkScope(t, e, c+`pay(?:ments|roll)/sa/x$`, "cloud.internal", "")
}

func TestAppendixD2Static(t *testing.T) {
	e, err := NewStaticExtractor("dc/corp-prod")
	if err != nil {
		t.Fatal(err)
	}
	checkScope(t, e, `^spiffe://prod\.internal/ns/checkout/sa/x$`, "prod.internal", "dc/corp-prod")
	if _, err := NewStaticExtractor("DC/x"); err == nil {
		t.Error("static extractor accepted an invalid scope")
	}
}

func TestAppendixD2Patterns(t *testing.T) {
	for _, v := range []struct {
		pattern, scope string
		match          bool
	}{
		{"*", "dc/corp-prod", true},
		{"cloud/fin-01/*", "cloud/fin-01", true},
		{"cloud/fin-01/*", "cloud/fin-01/payments", true},
		{"cloud/fin-01/*", "cloud/fin-01x/payments", false},
		{"cloud/fin-01", "cloud/fin-01/payments", false},
		{"dc/corp-prod", "dc/corp-prod", true},
	} {
		if got := ScopeMatches(v.pattern, v.scope); got != v.match {
			t.Errorf("ScopeMatches(%q, %q) = %v, want %v", v.pattern, v.scope, got, v.match)
		}
	}
	for p, want := range map[string]bool{
		"*": true, "cloud/fin-01": true, "cloud/fin-01/*": true,
		"": false, "*/x": false, "cloud/*/x": false, "cloud/": false,
	} {
		if got := ValidScopePattern(p); got != want {
			t.Errorf("ValidScopePattern(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestAppendixD2Paths(t *testing.T) {
	for p, want := range map[string]bool{
		"dc/corp-prod": true, "a": true, "cloud/fin-01/payments": true,
		"": false, "/dc": false, "dc/": false, "DC/x": false, "dc//x": false,
		"-a": false, "a-": false, strings.Repeat("a/", 8) + "a": false,
		strings.Repeat("a/", 7) + "a": true, strings.Repeat("a", 129): false,
	} {
		if got := ValidScopePath(p); got != want {
			t.Errorf("ValidScopePath(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestEXT18 re-verifies assumption EXT-18 on the Go version in use: the
// leading literal of a parsed pattern is exactly its fixed beginning.
func TestEXT18(t *testing.T) {
	ast, err := syntax.Parse(c+`(payments|hr)/sa/x$`, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	if ast.Op != syntax.OpConcat || len(ast.Sub) < 4 {
		t.Fatalf("not a concatenation: %v", ast)
	}
	if lit := ast.Sub[1]; lit.Op != syntax.OpLiteral || string(lit.Rune) != "spiffe://cloud.internal/acct/fin-01/tenant/" {
		t.Errorf("leading node is %v %q, want the whole fixed beginning as one literal", lit.Op, string(lit.Rune))
	}
	if ast.Sub[2].Op != syntax.OpCapture {
		t.Errorf("node after the literal is %v, want a capture group", ast.Sub[2].Op)
	}
}

var policyD2 = regexpolicy.Policy{MaxLength: 512, MinLiteralPathSegments: 2}

func checkScope(t *testing.T, e *Extractor, regex, td, want string) {
	t.Helper()
	got, err := e.SourceScope(regex, td)
	switch {
	case want == "" && !errors.Is(err, ErrScopeUnresolvable):
		t.Errorf("%q: got (%q, %v), want scope-unresolvable", regex, got, err)
	case want != "" && (err != nil || got != want):
		t.Errorf("%q: got (%q, %v), want %q", regex, got, err, want)
	}
}
