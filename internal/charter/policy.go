package charter

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

// SourceJurisdiction is the jurisdiction extractor of one trust domain
// (charter.source_jurisdictions, §3.9).
type SourceJurisdiction struct {
	TrustDomain          string `yaml:"trust_domain" json:"trustDomain"`
	Mode                 string `yaml:"mode" json:"mode"`
	Jurisdiction         string `yaml:"jurisdiction" json:"jurisdiction,omitempty"`
	PathRegex            string `yaml:"path_regex" json:"pathRegex,omitempty"`
	JurisdictionTemplate string `yaml:"jurisdiction_template" json:"jurisdictionTemplate,omitempty"`
}

// Extractor returns the extractor the entry describes.
func (s SourceJurisdiction) Extractor() (*Extractor, error) {
	switch s.Mode {
	case "static":
		return NewStaticExtractor(s.Jurisdiction)
	case "path_template":
		return NewPathTemplateExtractor(s.PathRegex, s.JurisdictionTemplate)
	}
	return nil, fmt.Errorf("mode must be static or path_template, not %q", s.Mode)
}

// NamePrefix is an entry of charter.name_prefixes (§3.8).
type NamePrefix struct {
	Jurisdictions []string `yaml:"jurisdictions" json:"jurisdictions"`
	Prefix        string   `yaml:"prefix" json:"prefix"`
	Resources     []string `yaml:"resources" json:"resources,omitempty"` // empty means all kinds
}

// Interconnects is charter.interconnects (ADR-14).
type Interconnects struct {
	DefaultCrossJurisdiction string             `yaml:"default_cross_jurisdiction" json:"defaultCrossJurisdiction"`
	Rules                    []InterconnectRule `yaml:"rules" json:"rules"`
}

type InterconnectRule struct {
	Name                string               `yaml:"name" json:"name"`
	From                []string             `yaml:"from" json:"from"`
	To                  []string             `yaml:"to" json:"to"`
	Action              string               `yaml:"action" json:"action"`
	AdditionalApprovals []AdditionalApproval `yaml:"additional_approvals" json:"additionalApprovals,omitempty"`
	DistinctApprovers   *bool                `yaml:"distinct_approvers" json:"distinctApprovers,omitempty"`
}

// AdditionalApproval is a party whose approvers decide a side of their own.
type AdditionalApproval struct {
	Name         string `yaml:"name" json:"name"`
	Jurisdiction string `yaml:"jurisdiction" json:"jurisdiction"`
}

// BreakGlassPolicy is an entry of break_glass.policies (ADR-12).
type BreakGlassPolicy struct {
	Jurisdictions []string      `yaml:"jurisdictions"`
	DefaultTTL    time.Duration `yaml:"default_ttl"`
	MaxTTL        time.Duration `yaml:"max_ttl"`
	MaxOpen       int           `yaml:"max_open"`
	WarnBefore    time.Duration `yaml:"warn_before"`
}

// MarshalJSON writes durations as whole seconds, in the canonical policy.
func (b BreakGlassPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Jurisdictions []string `json:"jurisdictions"`
		DefaultTTL    int64    `json:"defaultTtlSeconds"`
		MaxTTL        int64    `json:"maxTtlSeconds"`
		MaxOpen       int      `json:"maxOpen"`
		WarnBefore    int64    `json:"warnBeforeSeconds"`
	}{b.Jurisdictions, int64(b.DefaultTTL.Seconds()), int64(b.MaxTTL.Seconds()), b.MaxOpen, int64(b.WarnBefore.Seconds())})
}

// UnmarshalJSON reads the canonical form back, for the policy of a previous
// CONFIG_LOADED entry.
func (b *BreakGlassPolicy) UnmarshalJSON(data []byte) error {
	var v struct {
		Jurisdictions []string `json:"jurisdictions"`
		DefaultTTL    int64    `json:"defaultTtlSeconds"`
		MaxTTL        int64    `json:"maxTtlSeconds"`
		MaxOpen       int      `json:"maxOpen"`
		WarnBefore    int64    `json:"warnBeforeSeconds"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*b = BreakGlassPolicy{Jurisdictions: v.Jurisdictions, DefaultTTL: time.Duration(v.DefaultTTL) * time.Second, MaxTTL: time.Duration(v.MaxTTL) * time.Second,
		MaxOpen: v.MaxOpen, WarnBefore: time.Duration(v.WarnBefore) * time.Second}
	return nil
}

// Policy is the charter (§8.2 rule 16): its SHA-256 is stored on
// every change request.
type Policy struct {
	RequiredJurisdictions    []string             `json:"requiredJurisdictions"`
	RequireDistinctApprovers bool                 `json:"requireDistinctApproversAcrossJurisdictions"`
	SourceJurisdictions      []SourceJurisdiction `json:"sourceJurisdictions"`
	NamePrefixes             []NamePrefix         `json:"namePrefixes"`
	Interconnects            Interconnects        `json:"interconnects"`
	BreakGlassPolicies       []BreakGlassPolicy   `json:"breakGlassPolicies"`
}

// Decision is the outcome of the interconnection policy for a jurisdiction pair.
type Decision struct {
	Allowed bool
	// Rule is the deciding rule, "default" if none matched, or "" for a
	// same-jurisdiction pair, which never consults the policy.
	Rule                string
	AdditionalApprovals []AdditionalApproval
	DistinctApprovers   bool
}

// Evaluate applies the interconnection policy to a binding from sourceJurisdiction
// to targetJurisdiction (ADR-14 rules 2 to 4).
func (p *Policy) Evaluate(sourceJurisdiction, targetJurisdiction string) Decision {
	d := Decision{Allowed: true, DistinctApprovers: p.RequireDistinctApprovers}
	if sourceJurisdiction == targetJurisdiction {
		return d
	}
	for _, r := range p.Interconnects.Rules {
		if matchesAny(r.From, sourceJurisdiction) && matchesAny(r.To, targetJurisdiction) {
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
	d.Rule, d.Allowed = "default", p.Interconnects.DefaultCrossJurisdiction == "allow"
	return d
}

// ApprovalRequired reports whether sides in jurisdiction need an approver (ADR-09).
func (p *Policy) ApprovalRequired(jurisdiction string) bool {
	return matchesAny(p.RequiredJurisdictions, jurisdiction)
}

// BreakGlassPolicyFor returns the first break-glass policy covering jurisdiction,
// or nil.
func (p *Policy) BreakGlassPolicyFor(jurisdiction string) *BreakGlassPolicy {
	for i := range p.BreakGlassPolicies {
		if matchesAny(p.BreakGlassPolicies[i].Jurisdictions, jurisdiction) {
			return &p.BreakGlassPolicies[i]
		}
	}
	return nil
}

// UncoveredParty is an additional party of an interconnection rule whose
// jurisdiction no break-glass policy covers.
type UncoveredParty struct {
	Rule         string `json:"rule"`
	Party        string `json:"party"`
	Jurisdiction string `json:"jurisdiction"`
}

// PartiesWithoutBreakGlass lists the parties that make every break-glass
// change under their rule refused (ADR-12); none when no policy exists, as
// break-glass is then not in use.
func (p *Policy) PartiesWithoutBreakGlass() []UncoveredParty {
	if len(p.BreakGlassPolicies) == 0 {
		return nil
	}
	var found []UncoveredParty
	for _, r := range p.Interconnects.Rules {
		for _, a := range r.AdditionalApprovals {
			if p.BreakGlassPolicyFor(a.Jurisdiction) == nil {
				found = append(found, UncoveredParty{r.Name, a.Name, a.Jurisdiction})
			}
		}
	}
	return found
}

// Canonical returns the RFC 8785 canonical JSON of the policy, with the
// platforms sorted by name.
func (p *Policy) Canonical() ([]byte, error) {
	c := *p
	return jcs.Canonicalize(c)
}

// SHA256 returns the hex SHA-256 of the canonical policy.
func (p *Policy) SHA256() string {
	data, err := p.Canonical()
	if err != nil {
		panic(fmt.Sprintf("charter: canonical policy: %v", err)) // only plain types: cannot fail
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Loosening lists the changes from current to proposed that loosen the
// policy (§8.2, startup step 2): they are audited as
// CONFIG_APPROVAL_POLICY_WEAKENED.
func Loosening(current, proposed *Policy) []string {
	var out []string
	for _, s := range current.RequiredJurisdictions {
		if !slices.Contains(proposed.RequiredJurisdictions, s) {
			out = append(out, fmt.Sprintf("%q removed from required_jurisdictions", s))
		}
	}
	if current.RequireDistinctApprovers && !proposed.RequireDistinctApprovers {
		out = append(out, "require_distinct_approvers_across_jurisdictions turned off")
	}
	if current.Interconnects.DefaultCrossJurisdiction != "allow" && proposed.Interconnects.DefaultCrossJurisdiction == "allow" {
		out = append(out, "default_cross_jurisdiction changed to allow")
	}
	out = append(out, looserRules(current.Interconnects.Rules, proposed.Interconnects.Rules)...)
	out = append(out, removedRules(current.Interconnects.Rules, proposed.Interconnects.Rules)...)
	return append(out, raisedBreakGlass(current.BreakGlassPolicies, proposed.BreakGlassPolicies)...)
}

// looserRules reports the rules of proposed that loosen their counterpart in
// current, or waive distinct approvers.
func looserRules(current, proposed []InterconnectRule) []string {
	var out []string
	before := rulesByName(current)
	for i, r := range proposed {
		o, existed := before[r.Name]
		if r.DistinctApprovers != nil && !*r.DistinctApprovers && (!existed || o.rule.DistinctApprovers == nil || *o.rule.DistinctApprovers) {
			out = append(out, fmt.Sprintf("rule %q sets distinct_approvers: false", r.Name))
		}
		if !existed {
			continue
		}
		if o.rule.Action == "deny" && r.Action == "allow" {
			out = append(out, fmt.Sprintf("deny rule %q changed to allow", r.Name))
		}
		out = append(out, removedParties(o.rule, r)...)
		if r.Action == "deny" {
			out = append(out, shadowingAllows(r, o.index, proposed[:i], before)...)
		}
	}
	return out
}

// removedParties reports the additional parties of current that proposed,
// the same rule, no longer has.
func removedParties(current, proposed InterconnectRule) []string {
	var out []string
	for _, a := range current.AdditionalApprovals {
		if !slices.ContainsFunc(proposed.AdditionalApprovals, func(b AdditionalApproval) bool { return b.Name == a.Name }) {
			out = append(out, fmt.Sprintf("party %q removed from rule %q", a.Name, proposed.Name))
		}
	}
	return out
}

// shadowingAllows reports the allow rules now above deny rule r, which were
// not above it before and match some of its pairs.
func shadowingAllows(r InterconnectRule, oldIndex int, above []InterconnectRule, before map[string]indexedRule) []string {
	var out []string
	for _, a := range above {
		if a.Action != "allow" {
			continue
		}
		if prev, ok := before[a.Name]; ok && prev.index < oldIndex {
			continue
		}
		if overlap(a.From, r.From) && overlap(a.To, r.To) {
			out = append(out, fmt.Sprintf("deny rule %q now below allow rule %q", r.Name, a.Name))
		}
	}
	return out
}

// removedRules reports deny rules and additional parties that disappeared
// with their rule.
func removedRules(current, proposed []InterconnectRule) []string {
	var out []string
	after := rulesByName(proposed)
	for _, r := range current {
		if _, ok := after[r.Name]; ok {
			continue
		}
		if r.Action == "deny" {
			out = append(out, fmt.Sprintf("deny rule %q removed", r.Name))
		}
		for _, a := range r.AdditionalApprovals {
			out = append(out, fmt.Sprintf("party %q removed with rule %q", a.Name, r.Name))
		}
	}
	return out
}

// raisedBreakGlass reports break-glass policies, matched by their jurisdictions,
// whose max_ttl or max_open was raised.
func raisedBreakGlass(current, proposed []BreakGlassPolicy) []string {
	var out []string
	for _, o := range current {
		key := strings.Join(o.Jurisdictions, ",")
		i := slices.IndexFunc(proposed, func(b BreakGlassPolicy) bool { return strings.Join(b.Jurisdictions, ",") == key })
		if i < 0 {
			continue
		}
		n := proposed[i]
		if n.MaxTTL > o.MaxTTL {
			out = append(out, fmt.Sprintf("break-glass policy %v: max_ttl raised from %v to %v", o.Jurisdictions, o.MaxTTL, n.MaxTTL))
		}
		if n.MaxOpen > o.MaxOpen {
			out = append(out, fmt.Sprintf("break-glass policy %v: max_open raised from %d to %d", o.Jurisdictions, o.MaxOpen, n.MaxOpen))
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

func matchesAny(patterns []string, jurisdiction string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return JurisdictionMatches(p, jurisdiction) })
}

// overlap reports whether some jurisdiction matches a pattern of each list.
func overlap(a, b []string) bool {
	for _, p := range a {
		if slices.ContainsFunc(b, func(q string) bool { return PatternsOverlap(p, q) }) {
			return true
		}
	}
	return false
}

// PatternsOverlap reports whether some jurisdiction matches both patterns.
func PatternsOverlap(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	baseA, wildA := strings.CutSuffix(a, "/*")
	baseB, wildB := strings.CutSuffix(b, "/*")
	return baseA == baseB ||
		(wildA && strings.HasPrefix(baseB, baseA+"/")) ||
		(wildB && strings.HasPrefix(baseA, baseB+"/"))
}
