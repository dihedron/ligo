package regexpolicy

import (
	"errors"
	"regexp/syntax"
	"strings"
	"testing"
)

// prefix is P in the Appendix A.5 vectors.
const prefix = `^spiffe://prod\.internal/ns/checkout/sa/`

const trustDomain = "prod.internal"

// policyA5 is the policy the Appendix A.5 vectors are defined for.
var policyA5 = Policy{MaxLength: 512, MinLiteralPathSegments: 2}

type vector struct {
	pattern string
	rule    string // "" means accept
}

// TestAppendixA5 runs the normative reference vectors of Appendix A.5.
func TestAppendixA5(t *testing.T) {
	run(t, []vector{
		{prefix + `order-worker-[0-9]+$`, ""},
		{prefix + `[^/]+$`, ""},
		{prefix + `(worker-1|worker-2)$`, ""},
		{prefix + `worker-[0-9]{1,3}$`, ""},
		{prefix + `worker(?:-[a-z]+)*$`, ""},
		{prefix + `x(foo|)$`, ""},
		{prefix + `(?:api|web)/replica-[0-9]+$`, ""},
		{prefix + `x(?:[a-z]+|/)+$`, "7d"},
		{prefix + `x(/[a-z]+)*$`, "7d"},
		{prefix + `x(/[a-z]+)?$`, "7d"},
		{prefix + `x(?:/[a-z]+){0,3}$`, "7d"},
		{prefix + `x(?:a|b/c)+$`, "7d"},
		{prefix + `x.+$`, "7b"},
		{prefix + `x\S+$`, "7c"},
		{prefix + `x[^a]+$`, "7c"},
		{`(?i)` + prefix + `x$`, "7a"},
		{`^spiffe://prod\.internal/ns/a|.*$`, "4"},
		{`^spiffe://prod\.internal/ns/[a-z]+$`, "6"},
		{`^spiffe://test\.internal/ns/checkout/sa/x$`, "5"},
		{prefix + `x\$`, "4"},
	})
}

// TestAC02 is the pattern of acceptance scenario AC-02.
func TestAC02(t *testing.T) {
	run(t, []vector{{`^spiffe://prod\.internal/ns/a|.*$`, "4"}})
}

// TestAC03 covers each construct listed in acceptance scenario AC-03.
func TestAC03(t *testing.T) {
	run(t, []vector{
		{prefix + `(?i:x)$`, "7a"},
		{`(?m)` + prefix + `x$`, "4"}, // ^ and $ become line anchors
		{prefix + `x(?m:^)y$`, "7b"},
		{prefix + `x(?s:.)$`, "7b"},
		{prefix + `x.$`, "7b"},
		{prefix + `x[!-0]$`, "7c"},
		{prefix + `x(?:[a-z]+|/)+$`, "7d"},
		{prefix + `x(/[a-z]+)*$`, "7d"},
		{prefix + `x(/[a-z]+)?$`, "7d"},
		{prefix + `x\$`, "4"},
	})
}

// TestRules covers the rules the reference vectors do not reach.
func TestRules(t *testing.T) {
	run(t, []vector{
		{prefix + strings.Repeat("x", 512) + `$`, "1"},
		{prefix + "x\xff$", "1"},
		{prefix + `(x$`, "3"},
		{prefix + `x\z`, ""}, // \z is OpEndText, like $
		{`spiffe://prod\.internal/ns/checkout/sa/x$`, "4"},
		{`^spiffe://prod\.internal/ns/checkout/sa/x`, "4"},
		{`^spiffe://prod\.internal/ns/checkout/sa/x(?:\A)y$`, "7e"},
		{`^spiffe://prod\.internal/ns/checkout/sa/x(?:a$|b)$`, "7e"},
		{prefix + `x\x2f[a-z]*$`, ""},  // a fixed escaped slash is a literal
		{prefix + `x(?:\x2f)*$`, "7d"}, // under a repeat it is not
		{prefix + `x(?:a|b/c)$`, ""},   // fixed alternatives may spell two depths (A.3)
		{prefix + `x(?:/y){1}$`, ""},   // {1} is not a repeat
		{prefix + `x(?:/y){2}$`, "7d"},
		{`^spiffe://prod\.internal/ns/sa/x$`, ""},
		{`^spiffe://prod\.internal/ns/x$`, "6"},
	})
}

func TestTrustDomain(t *testing.T) {
	_, err := ValidateSVIDRegex(prefix+`x$`, "prod internal", policyA5)
	checkRule(t, prefix+`x$`, err, "2")
}

// TestCompiledProgram checks that the returned program is the one used for
// matching (rule 8).
func TestCompiledProgram(t *testing.T) {
	re, err := ValidateSVIDRegex(prefix+`order-worker-[0-9]+$`, trustDomain, policyA5)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{
		"spiffe://prod.internal/ns/checkout/sa/order-worker-12":   true,
		"spiffe://prod.internal/ns/checkout/sa/order-worker-12/x": false,
		"spiffe://prod.internal/ns/checkout/sa/order-worker-":     false,
		"xspiffe://prod.internal/ns/checkout/sa/order-worker-1":   false,
	} {
		if got := re.MatchString(id); got != want {
			t.Errorf("MatchString(%q) = %v, want %v", id, got, want)
		}
	}
}

func run(t *testing.T, vectors []vector) {
	t.Helper()
	for _, v := range vectors {
		re, err := ValidateSVIDRegex(v.pattern, trustDomain, policyA5)
		if v.rule == "" {
			if err != nil || re == nil {
				t.Errorf("%q: rejected (%v), want accepted", v.pattern, err)
			}
			continue
		}
		if re != nil {
			t.Errorf("%q: returned a program for a rejected pattern", v.pattern)
		}
		checkRule(t, v.pattern, err, v.rule)
	}
}

func checkRule(t *testing.T, pattern string, err error, rule string) {
	t.Helper()
	var invalid *InvalidError
	switch {
	case err == nil:
		t.Errorf("%q: accepted, want rule %s", pattern, rule)
	case !errors.Is(err, ErrInvalid) || !errors.As(err, &invalid):
		t.Errorf("%q: error %v is not an InvalidError", pattern, err)
	case invalid.Rule != rule:
		t.Errorf("%q: rejected by rule %s (%v), want rule %s", pattern, invalid.Rule, err, rule)
	}
}

// FuzzValidateSVIDRegex checks segment confinement (A.1) on accepted
// patterns: an identity they match never has more '/' than the pattern
// spells out literally, so no pattern reaches below a point in the tree.
func FuzzValidateSVIDRegex(f *testing.F) {
	for _, s := range []struct{ pattern, id string }{
		{prefix + `order-worker-[0-9]+$`, "spiffe://prod.internal/ns/checkout/sa/order-worker-7"},
		{prefix + `(?:api|web)/replica-[0-9]+$`, "spiffe://prod.internal/ns/checkout/sa/web/replica-1"},
		{prefix + `x(?:a|b/c)$`, "spiffe://prod.internal/ns/checkout/sa/xb/c"},
		{prefix + `x(/[a-z]+)*$`, "spiffe://prod.internal/ns/checkout/sa/x/a/b"},
		{prefix + `x[^a]+$`, "spiffe://prod.internal/ns/checkout/sa/x/b"},
	} {
		f.Add(s.pattern, s.id)
	}
	f.Fuzz(func(t *testing.T, pattern, id string) {
		re, err := ValidateSVIDRegex(pattern, trustDomain, policyA5)
		if err != nil || !re.MatchString(id) {
			return
		}
		ast, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			t.Fatalf("accepted pattern %q does not parse: %v", pattern, err)
		}
		if got, max := strings.Count(id, "/"), literalSlashes(ast); got > max {
			t.Fatalf("%q matches %q with %d '/', more than the %d it spells out", pattern, id, got, max)
		}
	})
}

// literalSlashes counts the '/' in every literal of the pattern.
func literalSlashes(n *syntax.Regexp) int {
	count := 0
	if n.Op == syntax.OpLiteral {
		for _, r := range n.Rune {
			if r == '/' {
				count++
			}
		}
	}
	for _, sub := range n.Sub {
		count += literalSlashes(sub)
	}
	return count
}
