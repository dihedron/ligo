// Package preview is the governance dry run of a planned creation (§7.2.3,
// POST /v1/admin/governance/evaluate), shared by the admin API and the
// UI's forms (§7.4): the scopes, the name-prefix check, the consent rule,
// the deciding interconnection rule and the sides with their basis. It
// stores nothing and calls no plugin; RBAC and the other validations
// happen when the request is filed.
package preview

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/targets"
)

// Evaluator evaluates planned creations with the services' rules.
type Evaluator struct {
	Sources  *sources.Service
	Targets  *targets.Service
	Bindings *bindings.Service
	Requests *changerequests.Service
}

type NameCheck struct {
	Valid  bool   `json:"valid"`
	Detail string `json:"detail,omitempty"`
}

type Interconnect struct {
	Rule   string `json:"rule"` // the deciding rule, or "default"
	Action string `json:"action"`
}

// Side is a side the creation would need, with its basis.
type Side struct {
	Side      string     `json:"side"`
	Scope     string     `json:"scope"`
	Basis     string     `json:"basis"`
	Decision  *string    `json:"decision"`
	DecidedBy string     `json:"decidedBy,omitempty"`
	DecidedAt *time.Time `json:"decidedAt,omitempty"`
}

// Evaluation is the governance outcome of a planned CREATE.
type Evaluation struct {
	ResourceType string            `json:"resourceType"`
	Name         string            `json:"name"`
	Scopes       map[string]string `json:"scopes"`
	NamePrefix   NameCheck         `json:"namePrefix"`
	Consent      string            `json:"consent"`
	Interconnect *Interconnect     `json:"interconnect"` // bindings across scopes only
	Sides        []Side            `json:"sides"`        // empty when the policy denies
}

func invalidBody(detail string) error {
	return &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: detail}
}

// Evaluate dry-runs body: a binding (resourceType BINDING), or a source or
// target body (kind Source or Target), for caller c.
func (v *Evaluator) Evaluate(ctx context.Context, c changerequests.Caller, body []byte) (*Evaluation, error) {
	var head struct {
		ResourceType string `json:"resourceType"`
		Kind         string `json:"kind"`
	}
	if json.Unmarshal(body, &head) != nil {
		return nil, invalidBody("body: not a JSON object")
	}
	var e *Evaluation
	var candidates []changerequests.Candidate
	var err error
	switch {
	case head.ResourceType == "BINDING":
		e, candidates, err = v.binding(ctx, c, body)
	case head.Kind == "Source":
		e, candidates, err = v.source(body)
	case head.Kind == "Target":
		e, candidates, err = v.target(body)
	default:
		err = invalidBody(`resourceType "BINDING", or kind "Source" or "Target"`)
	}
	if err != nil {
		return nil, err
	}
	e.Sides = []Side{}
	for _, sd := range changerequests.PreviewSides(candidates, c, v.Requests.Policy) {
		x := Side{Side: sd.Name, Scope: sd.Scope, Basis: sd.Basis, DecidedBy: sd.DecidedBy}
		if sd.Decision != "" {
			x.Decision = &sd.Decision
		}
		e.Sides = append(e.Sides, x)
	}
	return e, nil
}

func checkName(kind engine.Kind, name, scope string, prefixes []governance.NamePrefix) NameCheck {
	if err := engine.CheckName(kind, name, scope, prefixes); err != nil {
		return NameCheck{Detail: err.Error()}
	}
	return NameCheck{Valid: true}
}

// sourceScope derives the scope of a regex in a trust domain (§3.9).
func (v *Evaluator) sourceScope(td, regex string) (string, error) {
	x, ok := v.Sources.Rules.Extractors[td]
	if !ok {
		return "", invalidBody("trust domain " + td + " is accepted by no platform")
	}
	scope, err := x.SourceScope(regex, td)
	if err != nil {
		return "", &changerequests.Error{Status: 422, Slug: "scope-unresolvable", Detail: "the fixed beginning of the regex resolves to no scope (§3.9)"}
	}
	return scope, nil
}

// binding: the source by name (visible to the caller) or as {trustDomain,
// svidRegex}, the target by name (visible to the caller).
func (v *Evaluator) binding(ctx context.Context, c changerequests.Caller, b []byte) (*Evaluation, []changerequests.Candidate, error) {
	var req struct {
		ResourceType string          `json:"resourceType"`
		Name         string          `json:"name"`
		Source       json.RawMessage `json:"source"`
		Target       string          `json:"target"`
		AccessLevel  string          `json:"accessLevel"`
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, nil, invalidBody("body: " + err.Error())
	}
	var name string
	var inline struct {
		TrustDomain string `json:"trustDomain"`
		SVIDRegex   string `json:"svidRegex"`
	}
	var sourceScope string
	switch {
	case json.Unmarshal(req.Source, &name) == nil:
		s, err := v.Sources.Get(ctx, c, name)
		if err != nil {
			return nil, nil, err
		}
		sourceScope = s.Metadata.Scope
	case json.Unmarshal(req.Source, &inline) == nil && inline.TrustDomain != "":
		var err error
		if sourceScope, err = v.sourceScope(inline.TrustDomain, inline.SVIDRegex); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, invalidBody(`source: a name or {"trustDomain", "svidRegex"}`)
	}
	t, err := v.Targets.Get(ctx, c, req.Target)
	if err != nil {
		return nil, nil, err
	}
	if !slices.ContainsFunc(t.AccessLevels, func(l targets.AccessLevel) bool { return l.Name == req.AccessLevel }) {
		return nil, nil, invalidBody("accessLevel " + req.AccessLevel + " is not a level of " + req.Target)
	}
	m := t.Metadata
	e := &Evaluation{ResourceType: "BINDING", Name: req.Name, Consent: changerequests.ConsentAll,
		Scopes:     map[string]string{"source": sourceScope, "target": m.Scope, "platform": m.PlatformScope},
		NamePrefix: checkName(engine.KindBinding, req.Name, sourceScope, v.Bindings.Rules.NamePrefixes)}
	d := v.Requests.Policy.Evaluate(sourceScope, m.Scope)
	if d.Rule != "" {
		e.Interconnect = &Interconnect{Rule: d.Rule, Action: "allow"}
		if !d.Allowed {
			e.Interconnect.Action = "deny"
			return e, nil, nil
		}
	}
	return e, bindings.Candidates(sourceScope, m.Scope, m.Platform, d), nil
}

func (v *Evaluator) source(b []byte) (*Evaluation, []changerequests.Candidate, error) {
	var src sources.Source
	if err := json.Unmarshal(b, &src); err != nil {
		return nil, nil, invalidBody("body: " + err.Error())
	}
	scope, err := v.sourceScope(src.Identity.TrustDomain, src.Identity.SVIDRegex)
	if err != nil {
		return nil, nil, err
	}
	e := &Evaluation{ResourceType: "SOURCE", Name: src.Metadata.Name, Consent: changerequests.ConsentAll,
		Scopes:     map[string]string{"owner": scope},
		NamePrefix: checkName(engine.KindSource, src.Metadata.Name, scope, v.Sources.Rules.NamePrefixes)}
	return e, []changerequests.Candidate{{Side: "OWNER", Scope: scope}}, nil
}

// target: a PLATFORM side unless the scopes are equal (§3.7).
func (v *Evaluator) target(b []byte) (*Evaluation, []changerequests.Candidate, error) {
	var t targets.Target
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, nil, invalidBody("body: " + err.Error())
	}
	m := t.Metadata
	p, ok := v.Targets.Rules.Platforms[m.Platform]
	if !ok {
		return nil, nil, invalidBody("metadata.platform " + m.Platform + " is not a configured platform")
	}
	if !slices.ContainsFunc(p.TargetScopes, func(pat string) bool { return governance.ScopeMatches(pat, m.Scope) }) {
		return nil, nil, invalidBody("metadata.scope " + m.Scope + " is not in the target_scopes of " + p.Name)
	}
	e := &Evaluation{ResourceType: "TARGET", Name: m.Name, Consent: changerequests.ConsentAll,
		Scopes:     map[string]string{"owner": m.Scope, "platform": p.Scope},
		NamePrefix: checkName(engine.KindTarget, m.Name, m.Scope, v.Targets.Rules.NamePrefixes)}
	sides := []changerequests.Candidate{{Side: "OWNER", Scope: m.Scope, Platform: p.Name}}
	if p.Scope != m.Scope {
		sides = append(sides, changerequests.Candidate{Side: "PLATFORM", Scope: p.Scope, Platform: p.Name})
	}
	return e, sides, nil
}
