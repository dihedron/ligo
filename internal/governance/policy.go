package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dihedron/ligo/internal/jcs"
)

// SourceScope is the scope extractor of one trust domain
// (governance.source_scopes, §3.9).
type SourceScope struct {
	TrustDomain   string `yaml:"trust_domain" json:"trust_domain"`
	Mode          string `yaml:"mode" json:"mode"`
	Scope         string `yaml:"scope" json:"scope,omitempty"`
	PathRegex     string `yaml:"path_regex" json:"path_regex,omitempty"`
	ScopeTemplate string `yaml:"scope_template" json:"scope_template,omitempty"`
}

// Extractor returns the extractor the entry describes.
func (s SourceScope) Extractor() (*Extractor, error) {
	switch s.Mode {
	case "static":
		return NewStaticExtractor(s.Scope)
	case "path_template":
		return NewPathTemplateExtractor(s.PathRegex, s.ScopeTemplate)
	}
	return nil, fmt.Errorf("mode must be static or path_template, not %q", s.Mode)
}

// NamePrefix is an entry of governance.name_prefixes (§3.8).
type NamePrefix struct {
	Scopes    []string `yaml:"scopes" json:"scopes"`
	Prefix    string   `yaml:"prefix" json:"prefix"`
	Resources []string `yaml:"resources" json:"resources,omitempty"` // empty means all kinds
}

// Interconnects is governance.interconnects (ADR-14).
type Interconnects struct {
	DefaultCrossScope string             `yaml:"default_cross_scope" json:"default_cross_scope"`
	Rules             []InterconnectRule `yaml:"rules" json:"rules"`
}

type InterconnectRule struct {
	Name                string               `yaml:"name" json:"name"`
	From                []string             `yaml:"from" json:"from"`
	To                  []string             `yaml:"to" json:"to"`
	Action              string               `yaml:"action" json:"action"`
	AdditionalApprovals []AdditionalApproval `yaml:"additional_approvals" json:"additional_approvals,omitempty"`
	DistinctApprovers   *bool                `yaml:"distinct_approvers" json:"distinct_approvers,omitempty"`
}

// AdditionalApproval is a party whose approvers decide a side of their own.
type AdditionalApproval struct {
	Name  string `yaml:"name" json:"name"`
	Scope string `yaml:"scope" json:"scope"`
}

// BreakGlassPolicy is an entry of break_glass.policies (ADR-12).
type BreakGlassPolicy struct {
	Scopes     []string      `yaml:"scopes"`
	DefaultTTL time.Duration `yaml:"default_ttl"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
	MaxOpen    int           `yaml:"max_open"`
	WarnBefore time.Duration `yaml:"warn_before"`
}

// MarshalJSON writes durations as whole seconds, in the canonical policy.
func (b BreakGlassPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Scopes     []string `json:"scopes"`
		DefaultTTL int64    `json:"default_ttl"`
		MaxTTL     int64    `json:"max_ttl"`
		MaxOpen    int      `json:"max_open"`
		WarnBefore int64    `json:"warn_before"`
	}{b.Scopes, int64(b.DefaultTTL.Seconds()), int64(b.MaxTTL.Seconds()), b.MaxOpen, int64(b.WarnBefore.Seconds())})
}

// PlatformScopes is the governance part of a platform.
type PlatformScopes struct {
	Platform     string   `json:"platform"`
	Scope        string   `json:"scope"`
	TargetScopes []string `json:"target_scopes"`
}

// Policy is the governance policy (§8.2 rule 16): its SHA-256 is stored on
// every change request.
type Policy struct {
	RequiredScopes           []string           `json:"required_scopes"`
	RequireDistinctApprovers bool               `json:"require_distinct_approvers_across_scopes"`
	SourceScopes             []SourceScope      `json:"source_scopes"`
	NamePrefixes             []NamePrefix       `json:"name_prefixes"`
	Interconnects            Interconnects      `json:"interconnects"`
	BreakGlassPolicies       []BreakGlassPolicy `json:"break_glass_policies"`
	Platforms                []PlatformScopes   `json:"platforms"` // sorted by Canonical
}

// Decision is the outcome of the interconnection policy for a scope pair.
type Decision struct {
	Allowed bool
	// Rule is the deciding rule, "default" if none matched, or "" for a
	// same-scope pair, which never consults the policy.
	Rule                string
	AdditionalApprovals []AdditionalApproval
	DistinctApprovers   bool
}

// Evaluate applies the interconnection policy to a binding from sourceScope
// to targetScope (ADR-14 rules 2 to 4).
func (p *Policy) Evaluate(sourceScope, targetScope string) Decision {
	d := Decision{Allowed: true, DistinctApprovers: p.RequireDistinctApprovers}
	if sourceScope == targetScope {
		return d
	}
	for _, r := range p.Interconnects.Rules {
		if matchesAny(r.From, sourceScope) && matchesAny(r.To, targetScope) {
			d.Rule, d.Allowed = r.Name, r.Action == "allow"
			if d.Allowed {
				d.AdditionalApprovals = r.AdditionalApprovals
				if r.DistinctApprovers != nil {
					d.DistinctApprovers = *r.DistinctApprovers
				}
			}
			return d
		}
	}
	d.Rule, d.Allowed = "default", p.Interconnects.DefaultCrossScope == "allow"
	return d
}

// ApprovalRequired reports whether sides in scope need an approver (ADR-09).
func (p *Policy) ApprovalRequired(scope string) bool { return matchesAny(p.RequiredScopes, scope) }

// BreakGlassPolicyFor returns the first break-glass policy covering scope,
// or nil.
func (p *Policy) BreakGlassPolicyFor(scope string) *BreakGlassPolicy {
	for i := range p.BreakGlassPolicies {
		if matchesAny(p.BreakGlassPolicies[i].Scopes, scope) {
			return &p.BreakGlassPolicies[i]
		}
	}
	return nil
}

// Canonical returns the RFC 8785 canonical JSON of the policy, with the
// platforms sorted by name.
func (p *Policy) Canonical() ([]byte, error) {
	c := *p
	c.Platforms = slices.Clone(p.Platforms)
	slices.SortFunc(c.Platforms, func(a, b PlatformScopes) int { return strings.Compare(a.Platform, b.Platform) })
	return jcs.Canonicalize(c)
}

// SHA256 returns the hex SHA-256 of the canonical policy.
func (p *Policy) SHA256() string {
	data, err := p.Canonical()
	if err != nil {
		panic(fmt.Sprintf("governance: canonical policy: %v", err)) // only plain types: cannot fail
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Loosening lists the changes from old to new that loosen the policy
// (§8.2, startup step 2): they are audited as CONFIG_APPROVAL_POLICY_WEAKENED.
func Loosening(old, new *Policy) []string {
	var out []string
	for _, s := range old.RequiredScopes {
		if !slices.Contains(new.RequiredScopes, s) {
			out = append(out, fmt.Sprintf("%q removed from required_scopes", s))
		}
	}
	if old.RequireDistinctApprovers && !new.RequireDistinctApprovers {
		out = append(out, "require_distinct_approvers_across_scopes turned off")
	}
	if old.Interconnects.DefaultCrossScope != "allow" && new.Interconnects.DefaultCrossScope == "allow" {
		out = append(out, "default_cross_scope changed to allow")
	}
	oldRules := rulesByName(old.Interconnects.Rules)
	for i, r := range new.Interconnects.Rules {
		o, existed := oldRules[r.Name]
		if r.DistinctApprovers != nil && !*r.DistinctApprovers && (!existed || o.rule.DistinctApprovers == nil || *o.rule.DistinctApprovers) {
			out = append(out, fmt.Sprintf("rule %q sets distinct_approvers: false", r.Name))
		}
		if !existed {
			continue
		}
		if o.rule.Action == "deny" && r.Action == "allow" {
			out = append(out, fmt.Sprintf("deny rule %q changed to allow", r.Name))
		}
		for _, a := range o.rule.AdditionalApprovals {
			if !slices.ContainsFunc(r.AdditionalApprovals, func(b AdditionalApproval) bool { return b.Name == a.Name }) {
				out = append(out, fmt.Sprintf("party %q removed from rule %q", a.Name, r.Name))
			}
		}
		if r.Action != "deny" {
			continue
		}
		// allow rules now above this deny rule, which were not above it before
		// and match some of its pairs
		for _, above := range new.Interconnects.Rules[:i] {
			if above.Action != "allow" {
				continue
			}
			if prev, ok := oldRules[above.Name]; ok && prev.index < o.index {
				continue
			}
			if overlap(above.From, r.From) && overlap(above.To, r.To) {
				out = append(out, fmt.Sprintf("deny rule %q now below allow rule %q", r.Name, above.Name))
			}
		}
	}
	newRules := rulesByName(new.Interconnects.Rules)
	for _, r := range old.Interconnects.Rules {
		if _, ok := newRules[r.Name]; ok {
			continue
		}
		if r.Action == "deny" {
			out = append(out, fmt.Sprintf("deny rule %q removed", r.Name))
		}
		for _, a := range r.AdditionalApprovals {
			out = append(out, fmt.Sprintf("party %q removed with rule %q", a.Name, r.Name))
		}
	}
	for _, o := range old.BreakGlassPolicies {
		key := strings.Join(o.Scopes, ",")
		i := slices.IndexFunc(new.BreakGlassPolicies, func(b BreakGlassPolicy) bool { return strings.Join(b.Scopes, ",") == key })
		if i < 0 {
			continue
		}
		if n := new.BreakGlassPolicies[i]; n.MaxTTL > o.MaxTTL {
			out = append(out, fmt.Sprintf("break-glass policy %v: max_ttl raised from %v to %v", o.Scopes, o.MaxTTL, n.MaxTTL))
		}
		if n := new.BreakGlassPolicies[i]; n.MaxOpen > o.MaxOpen {
			out = append(out, fmt.Sprintf("break-glass policy %v: max_open raised from %d to %d", o.Scopes, o.MaxOpen, n.MaxOpen))
		}
	}
	return out
}

type indexedRule struct {
	index int
	rule  InterconnectRule
}

func rulesByName(rules []InterconnectRule) map[string]indexedRule {
	m := make(map[string]indexedRule, len(rules))
	for i, r := range rules {
		m[r.Name] = indexedRule{i, r}
	}
	return m
}

func matchesAny(patterns []string, scope string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return ScopeMatches(p, scope) })
}

// overlap reports whether some scope matches a pattern of each list.
func overlap(a, b []string) bool {
	for _, p := range a {
		if slices.ContainsFunc(b, func(q string) bool { return patternsOverlap(p, q) }) {
			return true
		}
	}
	return false
}

// patternsOverlap reports whether some scope matches both patterns.
func patternsOverlap(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	baseA, wildA := strings.CutSuffix(a, "/*")
	baseB, wildB := strings.CutSuffix(b, "/*")
	return baseA == baseB ||
		(wildA && strings.HasPrefix(baseB, baseA+"/")) ||
		(wildB && strings.HasPrefix(baseA, baseB+"/"))
}
