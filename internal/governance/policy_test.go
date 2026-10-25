package governance

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

// examplePolicy is the governance policy of the §8.1 example.
func examplePolicy() *Policy {
	return &Policy{
		RequiredScopes:           []string{"dc/corp-prod/*", "cloud/fin-01/*"},
		RequireDistinctApprovers: true,
		SourceScopes: []SourceScope{
			{TrustDomain: "prod.internal", Mode: "static", Scope: "dc/corp-prod"},
			{TrustDomain: "test.internal", Mode: "static", Scope: "dc/corp-test"},
			{TrustDomain: "cloud.internal", Mode: "path_template", PathRegex: `^/acct/([a-z0-9-]+)/tenant/([a-z0-9-]+)/`, ScopeTemplate: "cloud/${1}/${2}"},
		},
		NamePrefixes: []NamePrefix{{Scopes: []string{"cloud/*"}, Prefix: "{2}-{3}-", Resources: []string{"source", "target", "binding"}}},
		Interconnects: Interconnects{
			DefaultCrossScope: "deny",
			Rules: []InterconnectRule{
				{Name: "no-test-to-prod", From: []string{"dc/corp-test/*", "cloud/fin-01-test/*"}, To: []string{"dc/corp-prod/*"}, Action: "deny"},
				{Name: "within-dc-prod", From: []string{"dc/corp-prod/*"}, To: []string{"dc/corp-prod/*"}, Action: "allow"},
				{Name: "cloud-to-dc", From: []string{"cloud/*"}, To: []string{"dc/corp-prod/*"}, Action: "allow", AdditionalApprovals: []AdditionalApproval{{Name: "security", Scope: "sec/infosec"}}},
				{Name: "dc-to-cloud", From: []string{"dc/corp-prod/*"}, To: []string{"cloud/*"}, Action: "allow"},
				{Name: "cloud-within-account", From: []string{"cloud/fin-01/*"}, To: []string{"cloud/fin-01/*"}, Action: "allow", DistinctApprovers: ptr(false)},
			},
		},
		BreakGlassPolicies: []BreakGlassPolicy{
			{Scopes: []string{"dc/corp-prod/*"}, DefaultTTL: 4 * time.Hour, MaxTTL: 8 * time.Hour, MaxOpen: 5, WarnBefore: time.Hour},
			{Scopes: []string{"cloud/fin-01/*"}, DefaultTTL: 2 * time.Hour, MaxTTL: 4 * time.Hour, MaxOpen: 3, WarnBefore: 30 * time.Minute},
		},
		Platforms: []PlatformScopes{
			{Platform: "oracle-test-dynamic", Scope: "dc/corp-test", TargetScopes: []string{"dc/corp-test/*"}},
			{Platform: "oracle-prod", Scope: "dc/corp-prod", TargetScopes: []string{"dc/corp-prod/*"}},
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
		{"cloud/fin-01/payments", "cloud/fin-01/payments", "", nil}, // same scope: the policy is not consulted
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
	for scope, want := range map[string]bool{"dc/corp-prod": true, "dc/corp-prod/ledger": true, "dc/corp-test": false, "cloud/fin-01/payments": true, "cloud/fin-02/x": false} {
		if got := p.ApprovalRequired(scope); got != want {
			t.Errorf("ApprovalRequired(%q) = %v", scope, got)
		}
	}
	if bg := p.BreakGlassPolicyFor("cloud/fin-01/payments"); bg == nil || bg.MaxOpen != 3 {
		t.Errorf("break-glass policy: %+v", bg)
	}
	if bg := p.BreakGlassPolicyFor("dc/corp-test"); bg != nil {
		t.Errorf("break-glass policy for an uncovered scope: %+v", bg)
	}
}

// TestPolicyHash checks that the hash ignores the order of platforms and
// follows every policy change.
func TestPolicyHash(t *testing.T) {
	a, b := examplePolicy(), examplePolicy()
	slices.Reverse(b.Platforms)
	ha, hb := a.SHA256(), b.SHA256()
	if ha != hb || len(ha) != 64 {
		t.Errorf("hashes differ for the same policy: %s %s", ha, hb)
	}
	canonical, err := a.Canonical()
	if err != nil || !strings.Contains(string(canonical), `"max_ttl":28800`) || !strings.Contains(string(canonical), `"required_scopes":["dc/corp-prod/*","cloud/fin-01/*"]`) {
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
		{"AC-25: required scope removed", func(p *Policy) { p.RequiredScopes = p.RequiredScopes[1:] }, `"dc/corp-prod/*" removed from required_scopes`},
		{"distinct approvers off", func(p *Policy) { p.RequireDistinctApprovers = false }, "require_distinct_approvers_across_scopes turned off"},
		{"rule waives distinct approvers", func(p *Policy) { p.Interconnects.Rules[2].DistinctApprovers = ptr(false) }, `rule "cloud-to-dc" sets distinct_approvers: false`},
		{"deny rule removed", func(p *Policy) { p.Interconnects.Rules = p.Interconnects.Rules[1:] }, `deny rule "no-test-to-prod" removed`},
		{"deny rule changed to allow", func(p *Policy) { p.Interconnects.Rules[0].Action = "allow" }, `deny rule "no-test-to-prod" changed to allow`},
		{"deny rule moved below an overlapping allow", func(p *Policy) {
			r := p.Interconnects.Rules
			r[0], r[1] = r[1], r[0]
			r[0].From = []string{"*"}
		}, `deny rule "no-test-to-prod" now below allow rule "within-dc-prod"`},
		{"party removed", func(p *Policy) { p.Interconnects.Rules[2].AdditionalApprovals = nil }, `party "security" removed from rule "cloud-to-dc"`},
		{"default allow", func(p *Policy) { p.Interconnects.DefaultCrossScope = "allow" }, "default_cross_scope changed to allow"},
		{"max_ttl raised", func(p *Policy) { p.BreakGlassPolicies[0].MaxTTL = 12 * time.Hour }, "max_ttl raised"},
		{"max_open raised", func(p *Policy) { p.BreakGlassPolicies[1].MaxOpen = 4 }, "max_open raised"},
		{"required scope added", func(p *Policy) { p.RequiredScopes = append(p.RequiredScopes, "dc/corp-test") }, ""},
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
		if got := patternsOverlap(v.a, v.b); got != v.want {
			t.Errorf("patternsOverlap(%q, %q) = %v", v.a, v.b, got)
		}
	}
}
