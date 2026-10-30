package adminhttp

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/targets"
)

func (s *Server) governanceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/governance", s.getGovernance)
	mux.HandleFunc("POST /v1/admin/governance/evaluate", s.evaluate)
}

// getGovernance: the policy in force, as the canonical JSON its SHA-256
// is computed over (§8.2).
func (s *Server) getGovernance(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	p := s.Requests.Policy
	canonical, err := p.Canonical()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"policy": json.RawMessage(canonical), "sha256": p.SHA256()})
}

type nameCheck struct {
	Valid  bool   `json:"valid"`
	Detail string `json:"detail,omitempty"`
}

type interconnectDTO struct {
	Rule   string `json:"rule"` // the deciding rule, or "default"
	Action string `json:"action"`
}

// evaluation is the governance outcome of a planned CREATE.
type evaluation struct {
	ResourceType string            `json:"resourceType"`
	Name         string            `json:"name"`
	Scopes       map[string]string `json:"scopes"`
	NamePrefix   nameCheck         `json:"namePrefix"`
	Consent      string            `json:"consent"`
	Interconnect *interconnectDTO  `json:"interconnect"` // bindings across scopes only
	Sides        []sideDTO         `json:"sides"`        // empty when the policy denies
}

// evaluate is the dry run of a planned creation: a binding, or a source or
// target body. It stores nothing and calls no plugin; RBAC and the other
// validations happen when the request is filed.
func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !viewer(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	b, err := body(r)
	var head struct {
		ResourceType string `json:"resourceType"`
		Kind         string `json:"kind"`
	}
	if err == nil {
		if json.Unmarshal(b, &head) != nil {
			err = &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "body: not a JSON object"}
		}
	}
	var e *evaluation
	var candidates []changerequests.Candidate
	if err == nil {
		switch {
		case head.ResourceType == "BINDING":
			e, candidates, err = s.evaluateBinding(r, b)
		case head.Kind == "Source":
			e, candidates, err = s.evaluateSource(b)
		case head.Kind == "Target":
			e, candidates, err = s.evaluateTarget(b)
		default:
			err = &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: `resourceType "BINDING", or kind "Source" or "Target"`}
		}
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	e.Sides = []sideDTO{}
	for _, sd := range changerequests.PreviewSides(candidates, c, s.Requests.Policy) {
		x := sideDTO{Side: sd.Name, Scope: sd.Scope, Basis: sd.Basis, DecidedBy: sd.DecidedBy}
		if sd.Decision != "" {
			x.Decision = &sd.Decision
		}
		e.Sides = append(e.Sides, x)
	}
	reply(w, http.StatusOK, e)
}

func invalidBody(detail string) error {
	return &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: detail}
}

func checkName(kind engine.Kind, name, scope string, prefixes []governance.NamePrefix) nameCheck {
	if err := engine.CheckName(kind, name, scope, prefixes); err != nil {
		return nameCheck{Detail: err.Error()}
	}
	return nameCheck{Valid: true}
}

// sourceScope derives the scope of a regex in a trust domain (§3.9).
func (s *Server) sourceScope(td, regex string) (string, error) {
	x, ok := s.Sources.Rules.Extractors[td]
	if !ok {
		return "", invalidBody("trust domain " + td + " is accepted by no platform")
	}
	scope, err := x.SourceScope(regex, td)
	if err != nil {
		return "", &changerequests.Error{Status: 422, Slug: "scope-unresolvable", Detail: "the fixed beginning of the regex resolves to no scope (§3.9)"}
	}
	return scope, nil
}

// evaluateBinding: the source by name (visible to the caller) or as
// {trustDomain, svidRegex}, the target by name (visible to the caller).
func (s *Server) evaluateBinding(r *http.Request, b []byte) (*evaluation, []changerequests.Candidate, error) {
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
		v, err := s.Sources.Get(r.Context(), caller(r), name)
		if err != nil {
			return nil, nil, err
		}
		sourceScope = v.Metadata.Scope
	case json.Unmarshal(req.Source, &inline) == nil && inline.TrustDomain != "":
		var err error
		if sourceScope, err = s.sourceScope(inline.TrustDomain, inline.SVIDRegex); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, invalidBody(`source: a name or {"trustDomain", "svidRegex"}`)
	}
	t, err := s.Targets.Get(r.Context(), caller(r), req.Target)
	if err != nil {
		return nil, nil, err
	}
	if !slices.ContainsFunc(t.AccessLevels, func(l targets.AccessLevel) bool { return l.Name == req.AccessLevel }) {
		return nil, nil, invalidBody("accessLevel " + req.AccessLevel + " is not a level of " + req.Target)
	}
	m := t.Metadata
	e := &evaluation{ResourceType: "BINDING", Name: req.Name, Consent: changerequests.ConsentAll,
		Scopes:     map[string]string{"source": sourceScope, "target": m.Scope, "platform": m.PlatformScope},
		NamePrefix: checkName(engine.KindBinding, req.Name, sourceScope, s.Bindings.Rules.NamePrefixes)}
	d := s.Requests.Policy.Evaluate(sourceScope, m.Scope)
	if d.Rule != "" {
		e.Interconnect = &interconnectDTO{Rule: d.Rule, Action: "allow"}
		if !d.Allowed {
			e.Interconnect.Action = "deny"
			return e, nil, nil
		}
	}
	return e, bindings.Candidates(sourceScope, m.Scope, m.Platform, d), nil
}

func (s *Server) evaluateSource(b []byte) (*evaluation, []changerequests.Candidate, error) {
	var src sources.Source
	if err := json.Unmarshal(b, &src); err != nil {
		return nil, nil, invalidBody("body: " + err.Error())
	}
	scope, err := s.sourceScope(src.Identity.TrustDomain, src.Identity.SVIDRegex)
	if err != nil {
		return nil, nil, err
	}
	e := &evaluation{ResourceType: "SOURCE", Name: src.Metadata.Name, Consent: changerequests.ConsentAll,
		Scopes:     map[string]string{"owner": scope},
		NamePrefix: checkName(engine.KindSource, src.Metadata.Name, scope, s.Sources.Rules.NamePrefixes)}
	return e, []changerequests.Candidate{{Side: "OWNER", Scope: scope}}, nil
}

// evaluateTarget: a PLATFORM side unless the scopes are equal (§3.7).
func (s *Server) evaluateTarget(b []byte) (*evaluation, []changerequests.Candidate, error) {
	var t targets.Target
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, nil, invalidBody("body: " + err.Error())
	}
	m := t.Metadata
	p, ok := s.Targets.Rules.Platforms[m.Platform]
	if !ok {
		return nil, nil, invalidBody("metadata.platform " + m.Platform + " is not a configured platform")
	}
	if !slices.ContainsFunc(p.TargetScopes, func(pat string) bool { return governance.ScopeMatches(pat, m.Scope) }) {
		return nil, nil, invalidBody("metadata.scope " + m.Scope + " is not in the target_scopes of " + p.Name)
	}
	e := &evaluation{ResourceType: "TARGET", Name: m.Name, Consent: changerequests.ConsentAll,
		Scopes:     map[string]string{"owner": m.Scope, "platform": p.Scope},
		NamePrefix: checkName(engine.KindTarget, m.Name, m.Scope, s.Targets.Rules.NamePrefixes)}
	sides := []changerequests.Candidate{{Side: "OWNER", Scope: m.Scope, Platform: p.Name}}
	if p.Scope != m.Scope {
		sides = append(sides, changerequests.Candidate{Side: "PLATFORM", Scope: p.Scope, Platform: p.Name})
	}
	return e, sides, nil
}
