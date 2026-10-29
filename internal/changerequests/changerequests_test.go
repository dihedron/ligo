package changerequests

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
)

const (
	payments = "cloud/fin-01/payments" // self-service
	ledger   = "dc/corp-prod/ledger"   // requires approval
)

var policy = &governance.Policy{RequiredScopes: []string{"dc/corp-prod/*"}}

func grant(role string, scopes ...string) authz.Grant {
	return authz.Grant{Role: role, Scopes: scopes}
}

func status(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Slug
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// TestBuildSides: the basis of each side is fixed at creation (ADR-13 rule
// 6, §7.2.3 "Sides at creation").
func TestBuildSides(t *testing.T) {
	alice := authz.Principal{Name: "alice"}
	robot := authz.Principal{SPIFFEID: "spiffe://prod.internal/ci/robot"}
	automation := grant(config.RoleTrustedAutomation, "dc/corp-prod/*")
	automation.ApprovalReference = regexp.MustCompile(`^CHG[0-9]{7}$`)
	pinned := grant(config.RoleTrustedAutomation, "dc/corp-prod/*")
	pinned.Platforms = []string{"oracle-prod"}
	for name, tc := range map[string]struct {
		caller authz.Principal
		grants authz.Grants
		scope  string
		ref    string
		basis  string
		err    string
	}{
		"operator, self-service":       {alice, authz.Grants{grant(config.RoleOperator, "cloud/*")}, payments, "", BasisAuto, ""},
		"operator, approval required":  {alice, authz.Grants{grant(config.RoleOperator, "dc/*")}, ledger, "", BasisHuman, ""},
		"no role":                      {alice, nil, payments, "", BasisHuman, ""},
		"delegated":                    {robot, authz.Grants{automation}, ledger, "CHG0012345", BasisDelegated, ""},
		"delegated, no reference":      {robot, authz.Grants{automation}, ledger, "", "", "validation-failed"},
		"delegated, reference refused": {robot, authz.Grants{automation}, ledger, "INC1", "", "validation-failed"},
		"delegation, other platform":   {robot, authz.Grants{pinned}, ledger, "", BasisHuman, ""},
		"delegation needs a SPIFFE ID": {alice, authz.Grants{automation}, ledger, "CHG0012345", BasisHuman, ""},
	} {
		t.Run(name, func(t *testing.T) {
			sides, err := BuildSides([]Candidate{{Side: "OWNER", Scope: tc.scope, Platform: "pg-prod"}},
				Caller{Principal: tc.caller, Grants: tc.grants}, policy, tc.ref)
			if status(err) != tc.err {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
			if err != nil {
				return
			}
			s := sides[0]
			if s.Basis != tc.basis || s.ApprovalRequired != (tc.basis != BasisAuto) {
				t.Errorf("side %+v, want basis %s", s, tc.basis)
			}
			if decided := s.Decision == Approved; decided != (tc.basis != BasisHuman) {
				t.Errorf("side %+v: decided at creation = %t", s, decided)
			}
		})
	}
}

// TestConsent: ALL needs every side and fails on one decline; ANY needs one
// side and fails only when every side declined (ADR-13 rule 4).
func TestConsent(t *testing.T) {
	sides := func(decisions ...string) []Side {
		var out []Side
		for _, d := range decisions {
			out = append(out, Side{Decision: d})
		}
		return out
	}
	for _, tc := range []struct {
		consent            string
		sides              []Side
		complete, rejected bool
	}{
		{ConsentAll, sides(Approved, ""), false, false},
		{ConsentAll, sides(Approved, Approved), true, false},
		{ConsentAll, sides(Approved, Declined), false, true},
		{ConsentAny, sides("", Approved), true, false},
		{ConsentAny, sides(Declined, ""), false, false},
		{ConsentAny, sides(Declined, Declined), false, true},
	} {
		if c, r := Complete(tc.consent, tc.sides), Rejected(tc.consent, tc.sides); c != tc.complete || r != tc.rejected {
			t.Errorf("%s %+v: complete %t rejected %t", tc.consent, tc.sides, c, r)
		}
	}
}

// TestSelectSides: the sides a caller decides (§7.2.3 "Deciding sides").
func TestSelectSides(t *testing.T) {
	r := &Request{RequestedBy: "alice", DistinctApprovers: true, Sides: []Side{
		{Name: "SOURCE", Scope: payments, Basis: BasisHuman, ApprovalRequired: true},
		{Name: "TARGET", Scope: ledger, Basis: BasisHuman, ApprovalRequired: true},
		{Name: "PARTY:security", Scope: "sec/infosec", Basis: BasisHuman, ApprovalRequired: true},
	}}
	marco := Caller{Principal: authz.Principal{Name: "marco"}, Grants: authz.Grants{grant(config.RoleApprover, "cloud/*", "dc/*")}}
	olga := Caller{Principal: authz.Principal{Name: "olga"}, Grants: authz.Grants{grant(config.RoleOperator, "*")}}
	alice := Caller{Principal: authz.Principal{Name: "alice"}, Grants: authz.Grants{grant(config.RoleApprover, "*")}}
	nobody := Caller{Principal: authz.Principal{Name: "nobody"}}
	approvedByMarco := *r
	approvedByMarco.Sides = append([]Side{}, r.Sides...)
	approvedByMarco.Sides[0].Decision, approvedByMarco.Sides[0].DecidedBy = Approved, "marco"
	notDistinct := *r
	notDistinct.DistinctApprovers = false
	for name, tc := range map[string]struct {
		r       *Request
		caller  Caller
		approve bool
		side    string
		want    []string
		err     string
	}{
		"requester (four-eyes)":         {r, alice, true, "", nil, "four-eyes-violation"},
		"nothing eligible":              {r, nobody, true, "", nil, "forbidden"},
		"several sides, distinct":       {r, marco, true, "", nil, "side-required"},
		"one side chosen":               {r, marco, true, "TARGET", []string{"TARGET"}, ""},
		"side not eligible":             {r, marco, true, "PARTY:security", nil, "forbidden"},
		"already approved another side": {&approvedByMarco, marco, true, "TARGET", nil, "distinct-approver-required"},
		"declines are not limited":      {&approvedByMarco, marco, false, "", []string{"TARGET"}, ""},
		"not distinct: every side":      {&notDistinct, marco, true, "", []string{"SOURCE", "TARGET"}, ""},
		// an operator consents only where approval is not required, never for a party
		"operator": {r, olga, true, "", []string{"SOURCE"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := SelectSides(tc.r, tc.caller, policy, tc.approve, tc.side)
			if status(err) != tc.err || !equal(got, tc.want) {
				t.Errorf("got %v, %v; want %v, %q", got, err, tc.want, tc.err)
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestHash: the payload hash is over its JCS form, so key order and
// whitespace do not change it (§7.2.3).
func TestHash(t *testing.T) {
	a, err := Hash([]byte(`{"b": 1, "a": [true, "x"]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Hash([]byte(`{"a":["x"],"b":1}`))
	c, _ := Hash([]byte(`{"a":[true,"x"],"b":1}`))
	if len(a) != 64 || a != c || a == b {
		t.Errorf("hashes %s %s %s", a, b, c)
	}
}

// TestDecode: request bodies are strict, and their common fields bounded
// (§7.2.3).
func TestDecode(t *testing.T) {
	type body struct {
		Name string `json:"name"`
		Common
	}
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{`{"name":"x","approvalReference":"CHG0012345","automationContext":{"jobId":1}}`, true},
		{`{"name":"x","bogus":1}`, false},
		{`{"name":"x"} {"name":"y"}`, false},
		{`{"name":"x","approvalReference":"` + strings.Repeat("c", 129) + `"}`, false},
		{`{"name":"x","automationContext":[1]}`, false},
		{`{"name":"x","automationContext":{"pad":"` + strings.Repeat("p", 4096) + `"}}`, false},
	} {
		var b body
		if err := Decode([]byte(tc.body), &b, &b.Common); (err == nil) != tc.ok || err != nil && status(err) != "validation-failed" {
			t.Errorf("%.60s: %v", tc.body, err)
		}
	}
}

// TestBreakGlassSides: a side that needs a decision becomes BREAK_GLASS and
// needs the role on its scope; people only; at least one such side
// (§7.2.3 "Sides at creation", ADR-12 rule 1).
func TestBreakGlassSides(t *testing.T) {
	livia := authz.Principal{Name: "livia"}
	robot := authz.Principal{SPIFFEID: "spiffe://prod.internal/ci/robot"}
	bg := grant(config.RoleBreakGlass, "dc/corp-prod/*")
	op := grant(config.RoleOperator, "cloud/*")
	both := []Candidate{{Side: "TARGET", Scope: ledger}, {Side: "SOURCE", Scope: payments}}
	for name, tc := range map[string]struct {
		caller     authz.Principal
		grants     authz.Grants
		candidates []Candidate
		bases      string
		err        string
	}{
		"break-glass side":             {livia, authz.Grants{bg}, both[:1], "BREAK_GLASS", ""},
		"self-service side stays AUTO": {livia, authz.Grants{bg, op}, both, "BREAK_GLASS,AUTO", ""},
		"no role on the other side":    {livia, authz.Grants{bg}, both, "", "forbidden"},
		"SPIFFE principal":             {robot, authz.Grants{bg}, both[:1], "", "forbidden"},
		"no side needs a decision":     {livia, authz.Grants{bg, op}, both[1:], "", "validation-failed"},
	} {
		t.Run(name, func(t *testing.T) {
			sides, err := BreakGlassSides(tc.candidates, Caller{Principal: tc.caller, Grants: tc.grants}, policy)
			if status(err) != tc.err {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
			var bases []string
			for _, s := range sides {
				bases = append(bases, s.Basis)
				if s.Decision != Approved || s.ApprovalRequired != (s.Basis == BasisBreakGlass) {
					t.Errorf("side %+v", s)
				}
			}
			if got := strings.Join(bases, ","); got != tc.bases {
				t.Errorf("bases %s, want %s", got, tc.bases)
			}
		})
	}
}

// TestRatifiableSides: approvers of unratified BREAK_GLASS sides, never the
// requester, one side per person when distinct approvers are required.
func TestRatifiableSides(t *testing.T) {
	r := &Request{RequestedBy: "livia", DistinctApprovers: true, Sides: []Side{
		{Name: "SOURCE", Scope: payments, Basis: BasisAuto},
		{Name: "TARGET", Scope: ledger, Basis: BasisBreakGlass},
		{Name: "PARTY:security", Scope: "sec/infosec", Basis: BasisBreakGlass},
	}}
	marco := Caller{Principal: authz.Principal{Name: "marco"}, Grants: authz.Grants{grant(config.RoleApprover, "dc/*", "sec/*")}}
	livia := Caller{Principal: authz.Principal{Name: "livia"}, Grants: authz.Grants{grant(config.RoleApprover, "*")}}
	bob := Caller{Principal: authz.Principal{Name: "bob"}, Grants: authz.Grants{grant(config.RoleApprover, "dc/*")}}
	ratified := *r
	ratified.Sides = append([]Side{}, r.Sides...)
	ratified.Sides[1].RatifiedBy = "marco"
	for name, tc := range map[string]struct {
		r      *Request
		caller Caller
		side   string
		want   []string
		err    string
	}{
		"requester":                     {r, livia, "", nil, "four-eyes-violation"},
		"several sides, distinct":       {r, marco, "", nil, "side-required"},
		"one side chosen":               {r, marco, "TARGET", []string{"TARGET"}, ""},
		"AUTO sides are not ratified":   {r, marco, "SOURCE", nil, "forbidden"},
		"the only side":                 {r, bob, "", []string{"TARGET"}, ""},
		"already ratified":              {&ratified, bob, "", nil, "break-glass-not-open"},
		"ratified another side already": {&ratified, marco, "", nil, "distinct-approver-required"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RatifiableSides(tc.r, tc.caller, tc.side)
			if status(err) != tc.err || !equal(got, tc.want) {
				t.Errorf("got %v, %v; want %v, %q", got, err, tc.want, tc.err)
			}
		})
	}
}
