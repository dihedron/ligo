package instances

import (
	"maps"
	"slices"

	"github.com/dihedron/ligo/internal/flows"
)

// Source gives the instances in force; *Registry is one, Fixed another.
type Source interface {
	Current() *Set
}

// Fixed is a Source that never changes, for tests and tools.
type Fixed struct{ Set *Set }

func (f Fixed) Current() *Set { return f.Set }

// Set is an immutable snapshot of the ACTIVE instances.
type Set struct {
	byKind   map[Kind]map[string]*Definition
	allow    map[string]flows.Allowlist // by platform: its allowed_endpoints
	accepted map[string]bool            // trust domains some platform accepts sources from
}

// NewSet indexes definitions, which are checked and normalized; a later
// one replaces an earlier one of the same kind and name.
func NewSet(defs ...*Definition) *Set {
	s := &Set{byKind: map[Kind]map[string]*Definition{}, allow: map[string]flows.Allowlist{}, accepted: map[string]bool{}}
	for _, k := range Kinds {
		s.byKind[k] = map[string]*Definition{}
	}
	for _, d := range defs {
		k, err := d.KindOf()
		if err != nil {
			continue
		}
		s.byKind[k][d.Metadata.Name] = d
		if k == Platform {
			s.allow[d.Metadata.Name], _ = flows.ParseAllowlist(d.AllowedEndpoints()) // checked at filing
			for _, td := range d.AllowedSourceTrustDomains {
				s.accepted[td] = true
			}
		}
	}
	return s
}

// With is a copy of s with defs added or replaced.
func (s *Set) With(defs ...*Definition) *Set { return NewSet(append(s.All(), defs...)...) }

// Get is the instance of kind k called name.
func (s *Set) Get(k Kind, name string) (*Definition, bool) {
	d, ok := s.byKind[k][name]
	return d, ok
}

// Platform is the platform called name.
func (s *Set) Platform(name string) (*Definition, bool) { return s.Get(Platform, name) }

// List is the instances of kind k, by name.
func (s *Set) List(k Kind) []*Definition {
	m := s.byKind[k]
	out := make([]*Definition, 0, len(m))
	for _, name := range slices.Sorted(maps.Keys(m)) {
		out = append(out, m[name])
	}
	return out
}

// All is every instance, identity providers and secret stores first.
func (s *Set) All() []*Definition {
	var out []*Definition
	for _, k := range Kinds {
		out = append(out, s.List(k)...)
	}
	return out
}

// Allow is a platform's allowed_endpoints, parsed (§5.7).
func (s *Set) Allow(platform string) flows.Allowlist { return s.allow[platform] }

// Flows are the network flows an instance of kind k declares.
func (s *Set) Flows(k Kind, name string) []flows.Flow {
	if d, ok := s.Get(k, name); ok {
		return d.NetworkFlows
	}
	return nil
}

// AcceptedTrustDomains are the trust domains some platform accepts sources from.
func (s *Set) AcceptedTrustDomains() map[string]bool { return s.accepted }
