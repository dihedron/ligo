package charter

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

// examplePolicy is the charter of the §8.1 example.
func examplePolicy() *Policy {
	return &Policy{
		RequiredJurisdictions:    []string{"dc/corp-prod/*", "cloud/fin-01/*"},
		RequireDistinctApprovers: true,
		SourceJurisdictions: []SourceJurisdiction{
			{TrustDomain: "prod.internal", Mode: "static", Jurisdiction: "dc/corp-prod"},
			{TrustDomain: "test.internal", Mode: "static", Jurisdiction: "dc/corp-test"},
			{TrustDomain: "cloud.internal", Mode: "path_template", PathRegex: `^/acct/([a-z0-9-]+)/tenant/([a-z0-9-]+)/`, JurisdictionTemplate: "cloud/${1}/${2}"},
		},
		NamePrefixes: []NamePrefix{{Jurisdictions: []string{"cloud/*"}, Prefix: "{2}-{3}-", Resources: []string{"source", "target", "binding"}}},
		Interconnects: Interconnects{
			DefaultCrossJurisdiction: "deny",
			Rules: []InterconnectRule{
				{Name: "no-test-to-prod", From: []string{"dc/corp-test/*", "cloud/fin-01-test/*"}, To: []string{"dc/corp-prod/*"}, Action: "deny"},
				{Name: "within-dc-prod", From: []string{"dc/corp-prod/*"}, To: []string{"dc/corp-prod/*"}, Action: "allow"},
				{Name: "cloud-to-dc", From: []string{"cloud/*"}, To: []string{"dc/corp-prod/*"}, Action: "allow", AdditionalApprovals: []AdditionalApproval{{Name: "security", Jurisdiction: "sec/infosec"}}},
				{Name: "dc-to-cloud", From: []string{"dc/corp-prod/*"}, To: []string{"cloud/*"}, Action: "allow"},
				{Name: "cloud-within-account", From: []string{"cloud/fin-01/*"}, To: []string{"cloud/fin-01/*"}, Action: "allow", DistinctApprovers: ptr(false)},
			},
		},
		BreakGlassPolicies: []BreakGlassPolicy{
			{Jurisdictions: []string{"dc/corp-prod/*"}, DefaultTTL: 4 * time.Hour, MaxTTL: 8 * time.Hour, MaxOpen: 5, WarnBefore: time.Hour},
			{Jurisdictions: []string{"cloud/fin-01/*"}, DefaultTTL: 2 * time.Hour, MaxTTL: 4 * time.Hour, MaxOpen: 3, WarnBefore: 30 * time.Minute},
		},
	}
}

// TestAC51 is the policy part of acceptance scenario AC-51.
func TestAC51(t *testing.T) {
	p := examplePolicy()
	if d := p.Evaluate("dc/corp-test", "dc/corp-prod/ledger"); d.Allowed || d.Rule != "no-test-to-prod" {
		t.Errorf("test to prod: %+v", d)
	}
	if d := p.Evaluate("k8s/team", "dc/corp-test"); d.Allowed || d.Rule != "default" {
		t.Errorf("uncovered pair: %+v", d)
	}
}

// TestAC44 covers the four topologies of ADR-13.
func TestAC44(t *testing.T) {
	p := examplePolicy()
	for _, v := range []struct {
		source, target string
		rule           string
		parties        []string
	}{
		{"cloud/fin-01/payments", "cloud/fin-01/payments", "", nil}, // same jurisdiction: the policy is not consulted
		{"dc/corp-prod/ledger", "dc/corp-prod/ledger", "", nil},
		{"cloud/fin-01/payments", "dc/corp-prod/ledger", "cloud-to-dc", []string{"security"}},
		{"dc/corp-prod", "cloud/fin-01/payments", "dc-to-cloud", nil},
	} {
		d := p.Evaluate(v.source, v.target)
		var parties []string
		for _, a := range d.AdditionalApprovals {
			parties = append(parties, a.Name)
		}
		if !d.Allowed || d.Rule != v.rule || !slices.Equal(parties, v.parties) || !d.DistinctApprovers {
			t.Errorf("%s -> %s: %+v", v.source, v.target, d)
		}
	}
	if d := p.Evaluate("cloud/fin-01/payments", "cloud/fin-01/hr"); !d.Allowed || d.Rule != "cloud-within-account" || d.DistinctApprovers {
		t.Errorf("cloud-within-account: %+v", d)
	}
}

func TestApprovalRequired(t *testing.T) {
	p := examplePolicy()
	for jurisdiction, want := range map[string]bool{"dc/corp-prod": true, "dc/corp-prod/ledger": true, "dc/corp-test": false, "cloud/fin-01/payments": true, "cloud/fin-02/x": false} {
		if got := p.ApprovalRequired(jurisdiction); got != want {
			t.Errorf("ApprovalRequired(%q) = %v", jurisdiction, got)
		}
	}
	if bg := p.BreakGlassPolicyFor("cloud/fin-01/payments"); bg == nil || bg.MaxOpen != 3 {
		t.Errorf("break-glass policy: %+v", bg)
	}
	if bg := p.BreakGlassPolicyFor("dc/corp-test"); bg != nil {
		t.Errorf("break-glass policy for an uncovered jurisdiction: %+v", bg)
	}
}

// TestPolicyHash checks that the hash is stable and follows every policy
// change; platforms are not part of it (.specs/ligo-instances.md §8).
func TestPolicyHash(t *testing.T) {
	a, b := examplePolicy(), examplePolicy()
	ha, hb := a.SHA256(), b.SHA256()
	if ha != hb || len(ha) != 64 {
		t.Errorf("hashes differ for the same policy: %s %s", ha, hb)
	}
	canonical, err := a.Canonical()
	if err != nil || !strings.Contains(string(canonical), `"maxTtlSeconds":28800`) || !strings.Contains(string(canonical), `"requiredJurisdictions":["dc/corp-prod/*","cloud/fin-01/*"]`) {
		t.Errorf("canonical policy: (%s, %v)", canonical, err)
	}
	b.Interconnects.Rules[0].Action = "allow"
	if b.SHA256() == ha {
		t.Error("hash did not change with the policy")
	}
}

// TestLoosening covers each loosening change of §8.2, startup step 2,
// including AC-25.
func TestLoosening(t *testing.T) {
	for _, v := range []struct {
		name   string
		change func(*Policy)
		want   string // "" for a change that does not loosen
	}{
		{"AC-25: required jurisdiction removed", func(p *Policy) { p.RequiredJurisdictions = p.RequiredJurisdictions[1:] }, `"dc/corp-prod/*" removed from required_jurisdictions`},
		{"distinct approvers off", func(p *Policy) { p.RequireDistinctApprovers = false }, "require_distinct_approvers_across_jurisdictions turned off"},
		{"rule waives distinct approvers", func(p *Policy) { p.Interconnects.Rules[2].DistinctApprovers = ptr(false) }, `rule "cloud-to-dc" sets distinct_approvers: false`},
		{"deny rule removed", func(p *Policy) { p.Interconnects.Rules = p.Interconnects.Rules[1:] }, `deny rule "no-test-to-prod" removed`},
		{"deny rule changed to allow", func(p *Policy) { p.Interconnects.Rules[0].Action = "allow" }, `deny rule "no-test-to-prod" changed to allow`},
		{"deny rule moved below an overlapping allow", func(p *Policy) {
			r := p.Interconnects.Rules
			r[0], r[1] = r[1], r[0]
			r[0].From = []string{"*"}
		}, `deny rule "no-test-to-prod" now below allow rule "within-dc-prod"`},
		{"party removed", func(p *Policy) { p.Interconnects.Rules[2].AdditionalApprovals = nil }, `party "security" removed from rule "cloud-to-dc"`},
		{"default allow", func(p *Policy) { p.Interconnects.DefaultCrossJurisdiction = "allow" }, "default_cross_jurisdiction changed to allow"},
		{"max_ttl raised", func(p *Policy) { p.BreakGlassPolicies[0].MaxTTL = 12 * time.Hour }, "max_ttl raised"},
		{"max_open raised", func(p *Policy) { p.BreakGlassPolicies[1].MaxOpen = 4 }, "max_open raised"},
		{"required jurisdiction added", func(p *Policy) { p.RequiredJurisdictions = append(p.RequiredJurisdictions, "dc/corp-test") }, ""},
		{"deny rule added", func(p *Policy) {
			p.Interconnects.Rules = append([]InterconnectRule{{Name: "x", From: []string{"*"}, To: []string{"*"}, Action: "deny"}}, p.Interconnects.Rules...)
		}, ""},
		{"non-overlapping allow moved above a deny", func(p *Policy) {
			reorder(p, "dc-to-cloud", "no-test-to-prod", "within-dc-prod", "cloud-to-dc", "cloud-within-account")
		}, ""},
		{"overlapping allow moved above a deny", func(p *Policy) {
			reorder(p, "cloud-to-dc", "no-test-to-prod", "within-dc-prod", "dc-to-cloud", "cloud-within-account")
		}, `deny rule "no-test-to-prod" now below allow rule "cloud-to-dc"`},
		{"max_ttl lowered", func(p *Policy) { p.BreakGlassPolicies[0].MaxTTL = 5 * time.Hour }, ""},
	} {
		current, proposed := examplePolicy(), examplePolicy()
		v.change(proposed)
		got := Loosening(current, proposed)
		switch {
		case v.want == "" && len(got) > 0:
			t.Errorf("%s: reported %q", v.name, got)
		case v.want != "" && !slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, v.want) }):
			t.Errorf("%s: got %q, want %q", v.name, got, v.want)
		}
	}
}

// reorder puts the interconnect rules in the order of names.
func reorder(p *Policy, names ...string) {
	var rules []InterconnectRule
	for _, n := range names {
		i := slices.IndexFunc(p.Interconnects.Rules, func(r InterconnectRule) bool { return r.Name == n })
		rules = append(rules, p.Interconnects.Rules[i])
	}
	p.Interconnects.Rules = rules
}

func TestPatternsOverlap(t *testing.T) {
	for _, v := range []struct {
		a, b string
		want bool
	}{
		{"*", "x", true}, {"a/*", "a/b", true}, {"a/b", "a/*", true}, {"a/*", "a/b/*", true},
		{"a", "a", true}, {"a", "b", false}, {"a/*", "b/*", false}, {"a/b", "a/c", false}, {"a/bc/*", "a/b/*", false},
	} {
		if got := PatternsOverlap(v.a, v.b); got != v.want {
			t.Errorf("PatternsOverlap(%q, %q) = %v", v.a, v.b, got)
		}
	}
}

// TestPolicyRoundTrip: the canonical policy reads back to an equal policy,
// as startup does with the previous CONFIG_LOADED entry.
func TestPolicyRoundTrip(t *testing.T) {
	p := examplePolicy()
	data, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var back Policy
	if err := json.Unmarshal(data, &back); err != nil || back.SHA256() != p.SHA256() || len(Loosening(p, &back)) != 0 {
		t.Errorf("round trip: %v, %s != %s", err, back.SHA256(), p.SHA256())
	}
}

// TestPartiesWithoutBreakGlass: a party whose jurisdiction no break-glass policy
// covers is reported with its rule, since a break-glass change needing it is
// always refused (ADR-12); without any policy, break-glass is simply not in use.
func TestPartiesWithoutBreakGlass(t *testing.T) {
	p := &Policy{}
	p.Interconnects.Rules = []InterconnectRule{
		{Name: "plain"},
		{Name: "covered", AdditionalApprovals: []AdditionalApproval{{Name: "ops", Jurisdiction: "dc/ops"}}},
		{Name: "gap", AdditionalApprovals: []AdditionalApproval{{Name: "ops", Jurisdiction: "dc/ops"}, {Name: "security", Jurisdiction: "sec/infosec"}}},
	}
	if got := p.PartiesWithoutBreakGlass(); len(got) != 0 {
		t.Errorf("without policies: %v", got)
	}
	p.BreakGlassPolicies = []BreakGlassPolicy{{Jurisdictions: []string{"dc/*"}}}
	got := p.PartiesWithoutBreakGlass()
	if len(got) != 1 || got[0] != (UncoveredParty{Rule: "gap", Party: "security", Jurisdiction: "sec/infosec"}) {
		t.Errorf("got %v", got)
	}
}
