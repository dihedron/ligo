// Package sources registers and changes sources through change requests
// (§3.2, §7.2.3, §6.2.1): their validation pipeline, and the apply of their
// approved changes.
package sources

import (
	"fmt"
	"unicode/utf8"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Source is the desired state of a source (§3.2) without the fields ligo
// maintains; normalized, it is the payload of its change requests.
type Source struct {
	Kind         string            `json:"kind,omitempty"` // "Source" once normalized
	Metadata     Metadata          `json:"metadata"`
	Identity     Identity          `json:"identity"`
	DisplayName  string            `json:"displayName,omitempty"`
	Description  string            `json:"description,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	ExternalRefs map[string]string `json:"externalRefs,omitempty"`
	Contacts     []Contact         `json:"contacts,omitempty"`
	Visibility   Visibility        `json:"visibility"`
}

type Metadata struct {
	Name  string `json:"name"`
	Scope string `json:"scope,omitempty"` // derived from the regex (§3.9)
	State string `json:"state,omitempty"` // ACTIVE, DEPRECATED, RETIRED
}

type Identity struct {
	TrustDomain     string   `json:"trustDomain"`
	SVIDRegex       string   `json:"svidRegex"`
	SampleSPIFFEIDs []string `json:"sampleSpiffeIds"`
}

type Contact struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

type Visibility struct {
	Mode      string   `json:"mode"` // PRIVATE (default), LISTED, PUBLIC
	VisibleTo []string `json:"visibleTo,omitempty"`
}

// Rules are the parts of the configuration that validate sources.
type Rules struct {
	// Extractors derive the scope of a regex in each trust domain that some
	// platform accepts (§8.2 rule 15: each has a source_scopes entry).
	Extractors   map[string]*governance.Extractor
	NamePrefixes []governance.NamePrefix
	Regex        regexpolicy.Policy
}

// NewRules extracts the rules from a validated configuration.
func NewRules(cfg *config.Config) (*Rules, error) {
	accepted := map[string]bool{}
	for _, pp := range cfg.PlatformProviders {
		for _, p := range pp.Platforms {
			for _, td := range p.AllowedSourceTrustDomains {
				accepted[td] = true
			}
		}
	}
	r := &Rules{Extractors: map[string]*governance.Extractor{}, NamePrefixes: cfg.Governance.NamePrefixes, Regex: cfg.RegexPolicy}
	for _, ss := range cfg.Governance.SourceScopes {
		if !accepted[ss.TrustDomain] {
			continue
		}
		e, err := ss.Extractor()
		if err != nil {
			return nil, fmt.Errorf("source_scopes %s: %w", ss.TrustDomain, err)
		}
		r.Extractors[ss.TrustDomain] = e
	}
	return r, nil
}

func refuse(status int, slug, format string, args ...any) *changerequests.Error {
	return &changerequests.Error{Status: status, Slug: slug, Detail: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) *changerequests.Error {
	return refuse(422, "validation-failed", format, args...)
}

// validate runs the checks of the source pipeline that need no database
// (§7.2.3 steps 1 to 7, §3.7) on s, a new source if cur is nil, else an
// update of cur, and normalizes s. It returns the source's scope.
func (r *Rules) validate(s *Source, cur *Source) (string, error) {
	if s.Kind != "" && s.Kind != "Source" {
		return "", invalid("kind %q is not Source", s.Kind)
	}
	s.Kind = "Source"
	if !engine.ValidName(s.Metadata.Name) {
		return "", invalid("metadata.name %q is not a valid name (§3.8)", s.Metadata.Name)
	}
	if cur == nil {
		if s.Metadata.Scope != "" || s.Metadata.State != "" {
			return "", invalid("metadata.scope and metadata.state are set by ligo")
		}
		s.Metadata.State = "ACTIVE"
	} else {
		if s.Metadata.State == "" {
			s.Metadata.State = cur.Metadata.State
		}
		if err := transition(cur.Metadata.State, s.Metadata.State); err != nil {
			return "", err
		}
		if s.Identity.TrustDomain != cur.Identity.TrustDomain {
			return "", refuse(422, "immutable-field", "identity.trustDomain cannot change")
		}
	}
	td := s.Identity.TrustDomain
	if _, err := spiffeid.TrustDomainFromString(td); err != nil {
		return "", invalid("identity.trustDomain %q: %v", td, err)
	}
	extractor, ok := r.Extractors[td]
	if !ok {
		return "", invalid("identity.trustDomain %q is accepted by no platform", td)
	}
	re, err := regexpolicy.ValidateSVIDRegex(s.Identity.SVIDRegex, td, r.Regex)
	if err != nil {
		return "", invalid("identity.svidRegex: %v", err)
	}
	scope, err := extractor.SourceScope(s.Identity.SVIDRegex, td)
	if err != nil {
		return "", refuse(422, "scope-unresolvable", "the fixed beginning of identity.svidRegex resolves to no scope (§3.9)")
	}
	if cur == nil {
		if err := engine.CheckName(engine.KindSource, s.Metadata.Name, scope, r.NamePrefixes); err != nil {
			return "", invalid("metadata.name: %v", err)
		}
	} else {
		if s.Metadata.Scope != "" && s.Metadata.Scope != cur.Metadata.Scope || scope != cur.Metadata.Scope {
			return "", refuse(422, "immutable-field", "the scope of the source cannot change (it is %s)", cur.Metadata.Scope)
		}
		if err := r.narrows(cur.Identity.SVIDRegex, s.Identity.SVIDRegex); err != nil {
			return "", err
		}
	}
	s.Metadata.Scope = scope
	if len(s.Identity.SampleSPIFFEIDs) > 20 {
		return "", invalid("identity.sampleSpiffeIds: at most 20")
	}
	if s.Identity.SampleSPIFFEIDs == nil {
		s.Identity.SampleSPIFFEIDs = []string{}
	}
	for _, sample := range s.Identity.SampleSPIFFEIDs {
		id, err := spiffeid.FromString(sample)
		if err != nil || id.TrustDomain().Name() != td || !re.MatchString(sample) {
			return "", refuse(422, "sample-not-matched", "sample %q is not matched by identity.svidRegex in %s", sample, td)
		}
	}
	return scope, r.validateMetadata(s)
}

// narrows checks that proposed matches a subset of what current matches
// (§3.10); undecided is not a narrowing.
func (r *Rules) narrows(current, proposed string) error {
	if proposed == current {
		return nil
	}
	n, err := regexpolicy.CheckNarrowing(current, proposed, r.Regex.NarrowingStateLimit)
	switch {
	case err != nil:
		return refuse(422, "widening-not-allowed", "undecided: %v", err)
	case !n.Narrower:
		return refuse(422, "widening-not-allowed", "wider: the new regex also matches %s", n.Witness)
	}
	return nil
}

func (r *Rules) validateMetadata(s *Source) error {
	switch {
	case utf8.RuneCountInString(s.DisplayName) > 128:
		return invalid("displayName: at most 128 characters")
	case utf8.RuneCountInString(s.Description) > 4096:
		return invalid("description: at most 4096 characters")
	}
	return s.Visibility.Normalize()
}

// Normalize checks a visibility (§3.2) and defaults its mode to PRIVATE;
// targets share it (§3.3).
func (v *Visibility) Normalize() error {
	if v.Mode == "" {
		v.Mode = "PRIVATE"
	}
	switch v.Mode {
	case "LISTED":
		if len(v.VisibleTo) == 0 {
			return invalid("visibility.visibleTo is required with LISTED")
		}
		for _, p := range v.VisibleTo {
			if !governance.ValidScopePattern(p) {
				return invalid("visibility.visibleTo: %q is not a scope pattern", p)
			}
		}
	case "PRIVATE", "PUBLIC":
		if len(v.VisibleTo) > 0 {
			return invalid("visibility.visibleTo is only for LISTED")
		}
	default:
		return invalid("visibility.mode %q is not PRIVATE, LISTED or PUBLIC", v.Mode)
	}
	return nil
}

// transition checks a change of state (§7.2.3 step 9); no change is allowed.
func transition(from, to string) error {
	ok := from == to && from != "RETIRED"
	switch from + ">" + to {
	case "ACTIVE>DEPRECATED", "DEPRECATED>ACTIVE", "ACTIVE>RETIRED", "DEPRECATED>RETIRED":
		ok = true
	}
	if !ok {
		return refuse(409, "invalid-transition", "a source cannot go from %s to %s", from, to)
	}
	return nil
}
