package regexpolicy

import (
	"errors"
	"regexp"
	"regexp/syntax"
	"testing"
)

// p is P in the Appendix D.3 vectors.
const p = `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/`

const witnessPrefix = "spiffe://cloud.internal/acct/fin-01/tenant/payments/"

// TestAppendixD3 runs the normative reference vectors of Appendix D.3.
func TestAppendixD3(t *testing.T) {
	for i, v := range []struct {
		current, proposed string
		limit             int
		narrower          bool
		witness           string // "" for a narrowing
		undecided         bool
	}{
		{current: p + `sa/ledger-[0-9]+$`, proposed: p + `sa/ledger-[0-9]$`, narrower: true},
		{current: p + `sa/ledger-[0-9]$`, proposed: p + `sa/ledger-[0-9]+$`, witness: "sa/ledger-00"},
		{current: p + `sa/[a-z]+$`, proposed: p + `sa/(ledger|audit)$`, narrower: true},
		{current: p + `sa/(ledger|audit)$`, proposed: p + `sa/[a-z]+$`, witness: "sa/a"},
		{current: p + `sa/ledger-[0-9]+$`, proposed: p + `sa/ledger-[0-9a-z]+$`, witness: "sa/ledger-a"},
		{current: p + `sa/w-[0-9]+$`, proposed: p + `sa/w-[0-9]{2,3}$`, narrower: true},
		{current: p + `sa/w-[0-9]{2,3}$`, proposed: p + `sa/w-[0-9]{1,3}$`, witness: "sa/w-0"},
		{current: p + `sa/x-[^/]+$`, proposed: p + `sa/x-[a-f0-9]+$`, narrower: true},
		{current: p + `ns/a/sa/x$`, proposed: p + `ns/b/sa/x$`, witness: "ns/b/sa/x"},
		{current: p + `sa/ledger-[0-9]+$`, proposed: p + `sa/ledger-[0-9]+$`, narrower: true},
		{current: p + `sa/(a|b)*b(a|b){14}$`, proposed: p + `sa/(a|b)*a(a|b){14}$`, limit: 1000, undecided: true},
	} {
		limit := v.limit
		if limit == 0 {
			limit = DefaultPolicy().NarrowingStateLimit
		}
		got, err := CheckNarrowing(v.current, v.proposed, limit)
		switch {
		case v.undecided:
			if !errors.Is(err, ErrUndecided) || got.Narrower {
				t.Errorf("vector %d: got (%+v, %v), want undecided", i+1, got, err)
			}
		case err != nil:
			t.Errorf("vector %d: %v", i+1, err)
		case got.Narrower != v.narrower:
			t.Errorf("vector %d: narrower = %v, want %v", i+1, got.Narrower, v.narrower)
		case !v.narrower && got.Witness != witnessPrefix+v.witness:
			t.Errorf("vector %d: witness %q, want %q", i+1, got.Witness, witnessPrefix+v.witness)
		}
	}
}

// pool are the tails, after P + "sa/", compared pairwise by
// TestAC81BruteForce.
var pool = []string{
	`a$`, `[ab]+$`, `a[ab]*$`, `(a|b)$`, `[ab0]{1,3}$`, `a-[0-9]+$`,
	`[^/]+$`, `(?:a|b)/0$`, `[a-]+$`, `b?a$`, `[ab]{2}$`,
}

// TestAC81BruteForce is acceptance scenario AC-81: the results agree with
// brute-force enumeration over short strings, and every witness is matched
// by the new regex and not by the current one.
func TestAC81BruteForce(t *testing.T) {
	tails := enumerate("ab0-/", 6)
	for _, cur := range pool {
		for _, prop := range pool {
			checkAgainstEnumeration(t, p+`sa/`+cur, p+`sa/`+prop, tails)
		}
	}
}

// checkAgainstEnumeration compares CheckNarrowing with the first tail
// matched by the proposed regex only.
func checkAgainstEnumeration(t *testing.T, current, proposed string, tails []string) {
	t.Helper()
	got, err := CheckNarrowing(current, proposed, DefaultPolicy().NarrowingStateLimit)
	if err != nil {
		t.Errorf("(%s, %s): %v", current, proposed, err)
		return
	}
	shortest := firstOnlyMatched(current, proposed, tails)
	if got.Narrower {
		if shortest != "" {
			t.Errorf("(%s, %s): narrowing, but %q is matched only by the new regex", current, proposed, shortest)
		}
		return
	}
	checkWitness(t, current, proposed, got.Witness)
	if shortest != "" && len([]rune(got.Witness)) > len([]rune(shortest)) {
		t.Errorf("(%s, %s): witness %q is longer than %q", current, proposed, got.Witness, shortest)
	}
}

// firstOnlyMatched returns the first identity, over the tails, matched by
// proposed and not by current, or "".
func firstOnlyMatched(current, proposed string, tails []string) string {
	rc, rp := regexp.MustCompile(current), regexp.MustCompile(proposed)
	for _, tail := range tails {
		if id := witnessPrefix + "sa/" + tail; rp.MatchString(id) && !rc.MatchString(id) {
			return id
		}
	}
	return ""
}

// TestEXT19 re-verifies assumption EXT-19 on the Go version in use: the
// patterns compile only to the instruction kinds the check handles, with ^
// and $ as EmptyBeginText and EmptyEndText.
func TestEXT19(t *testing.T) {
	for _, tail := range append(pool, `ledger-[0-9]{2,3}$`, `(ledger|audit)$`, `x-[^/]+$`) {
		prog, err := compileForNarrowing(p + `sa/` + tail)
		if err != nil {
			t.Errorf("%s: %v", tail, err)
			continue
		}
		var begin, end bool
		for _, in := range prog.Inst {
			if in.Op == syntax.InstEmptyWidth {
				begin = begin || syntax.EmptyOp(in.Arg) == syntax.EmptyBeginText
				end = end || syntax.EmptyOp(in.Arg) == syntax.EmptyEndText
			}
		}
		if !begin || !end {
			t.Errorf("%s: ^ and $ did not compile to EmptyBeginText and EmptyEndText", tail)
		}
	}
}

func TestNarrowingRefusals(t *testing.T) {
	for _, v := range []struct {
		current, proposed string
		err               error
	}{
		{p + `sa/a$`, `spiffe://cloud\.internal/x$`, ErrNotAnchored},
		{p + `sa/a\$`, p + `sa/a$`, ErrNotAnchored},
		{p + `sa/a$`, p + `sa/(?i)a$`, ErrUnsupported},
		{p + `sa/a\b$`, p + `sa/a$`, ErrUnsupported},
	} {
		if got, err := CheckNarrowing(v.current, v.proposed, 100); !errors.Is(err, v.err) || got.Narrower {
			t.Errorf("(%q, %q): got (%+v, %v), want %v", v.current, v.proposed, got, err, v.err)
		}
	}
}

// FuzzCheckNarrowing checks every witness against regexp, and that a regex
// always narrows itself unless undecided.
func FuzzCheckNarrowing(f *testing.F) {
	for i := range pool {
		f.Add(pool[i], pool[(i+1)%len(pool)])
	}
	f.Fuzz(func(t *testing.T, cur, prop string) {
		current, proposed := p+`sa/`+cur, p+`sa/`+prop
		for _, r := range []string{current, proposed} {
			if _, err := ValidateSVIDRegex(r, "cloud.internal", DefaultPolicy()); err != nil {
				return
			}
		}
		got, err := CheckNarrowing(current, proposed, 2000)
		if err != nil {
			if got.Narrower {
				t.Fatalf("(%q, %q): narrowing despite %v", cur, prop, err)
			}
			return
		}
		if !got.Narrower {
			checkWitness(t, current, proposed, got.Witness)
		}
		if self, err := CheckNarrowing(current, current, 2000); err == nil && !self.Narrower {
			t.Fatalf("%q does not narrow itself: witness %q", cur, self.Witness)
		}
	})
}

func checkWitness(t *testing.T, current, proposed, witness string) {
	t.Helper()
	if !regexp.MustCompile(proposed).MatchString(witness) || regexp.MustCompile(current).MatchString(witness) {
		t.Errorf("(%s, %s): witness %q is not matched by the new regex only", current, proposed, witness)
	}
}

// enumerate returns every string over alphabet of length 1 to n, shortest
// first.
func enumerate(alphabet string, n int) []string {
	var out, level []string
	level = []string{""}
	for i := 0; i < n; i++ {
		var next []string
		for _, s := range level {
			for _, r := range alphabet {
				next = append(next, s+string(r))
			}
		}
		out = append(out, next...)
		level = next
	}
	return out
}

// TestOverlap: two regexes overlap when one identity matches both; the
// witness is a shortest such identity (T-34).
func TestOverlap(t *testing.T) {
	const p = `^spiffe://prod\.internal/ns/payments/sa/`
	for _, tc := range []struct {
		a, b     string
		overlaps bool
		witness  string
	}{
		{p + `ledger-[0-9]+$`, p + `ledger-1[0-9]$`, true, "spiffe://prod.internal/ns/payments/sa/ledger-10"},
		{p + `ledger-[0-9]+$`, p + `batch-[0-9]+$`, false, ""},
		{p + `[a-z]+-1$`, p + `ledger-[0-9]$`, true, "spiffe://prod.internal/ns/payments/sa/ledger-1"},
		{p + `x$`, p + `x$`, true, "spiffe://prod.internal/ns/payments/sa/x"},
	} {
		o, err := CheckOverlap(tc.a, tc.b, 10000)
		if err != nil || o.Overlaps != tc.overlaps || o.Witness != tc.witness {
			t.Errorf("%s ∩ %s: %+v, %v", tc.a, tc.b, o, err)
		}
		if o.Overlaps && (!regexp.MustCompile(tc.a).MatchString(o.Witness) || !regexp.MustCompile(tc.b).MatchString(o.Witness)) {
			t.Errorf("witness %q does not match both", o.Witness)
		}
	}
	if _, err := CheckOverlap(`^a`, `^a$`, 100); !errors.Is(err, ErrNotAnchored) {
		t.Errorf("unanchored: %v", err)
	}
}
