// Package authz maps principals to the roles of their authorization
// bindings, on governance scopes (§7.2.2).
package authz

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
)

// Principal is an authenticated caller: a SPIFFE ID (mTLS) or an LDAP user
// with the DNs of its groups.
type Principal struct {
	Name     string
	SPIFFEID string
	Groups   []string
}

// Grant is an authorization binding that applies to a principal.
type Grant struct {
	Role      string
	Scopes    []string
	Platforms []string
	// ApprovalReference is the compiled approval_reference_pattern, or nil.
	ApprovalReference *regexp.Regexp
	RateLimit         *config.APIRateLimit
}

func (g *Grant) covers(scope string) bool {
	return slices.ContainsFunc(g.Scopes, func(p string) bool { return governance.ScopeMatches(p, scope) })
}

// coversPlatform reports whether a trusted_automation grant extends to
// platform; an empty platform means a resource without one, such as a
// source.
func (g *Grant) coversPlatform(platform string) bool {
	return len(g.Platforms) == 0 || platform == "" || slices.Contains(g.Platforms, platform)
}

// Authorizer holds the authorization bindings of the configuration.
type Authorizer struct {
	bindings []binding
}

type binding struct {
	groupDN  string // lower case
	spiffeID string
	grant    Grant
}

// New compiles the authorization bindings; they have passed config.Validate.
func New(bindings []config.RoleBinding) (*Authorizer, error) {
	a := &Authorizer{}
	for _, b := range bindings {
		g := Grant{Role: b.Role, Scopes: b.Scopes, Platforms: b.Platforms, RateLimit: b.RateLimit}
		if b.ApprovalReferencePattern != "" {
			re, err := regexp.Compile(b.ApprovalReferencePattern)
			if err != nil {
				return nil, fmt.Errorf("authz: approval_reference_pattern of %s: %w", b.SPIFFEID, err)
			}
			g.ApprovalReference = re
		}
		a.bindings = append(a.bindings, binding{groupDN: strings.ToLower(b.LDAPGroupDN), spiffeID: b.SPIFFEID, grant: g})
	}
	return a, nil
}

// For returns the grants of p: by SPIFFE ID for a SPIFFE principal, by group
// DN (ignoring case) for an LDAP one, never both.
func (a *Authorizer) For(p Principal) Grants {
	var out Grants
	for _, b := range a.bindings {
		switch {
		case p.SPIFFEID != "":
			if b.spiffeID != "" && b.spiffeID == p.SPIFFEID {
				out = append(out, b.grant)
			}
		case b.groupDN != "" && slices.ContainsFunc(p.Groups, func(g string) bool { return strings.EqualFold(g, b.groupDN) }):
			out = append(out, b.grant)
		}
	}
	return out
}

// Grants are the effective grants of a principal: the union of its bindings.
type Grants []Grant

func (gs Grants) has(match func(*Grant) bool) bool {
	for i := range gs {
		if match(&gs[i]) {
			return true
		}
	}
	return false
}

// FullAccess reports the admin.full_access role.
func (gs Grants) FullAccess() bool {
	return gs.has(func(g *Grant) bool { return g.Role == config.RoleFullAccess })
}

// Sees reports whether any role other than break_glass covers one of the
// scopes of a resource (its scope; a target's platform scope; a binding's
// three scopes and its parties').
func (gs Grants) Sees(scopes ...string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool {
		return g.Role != config.RoleBreakGlass && slices.ContainsFunc(scopes, g.covers)
	})
}

// ActsFor reports whether the principal holds operator rights on scope: as
// operator, or as trusted_automation covering scope and platform.
func (gs Grants) ActsFor(scope, platform string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool {
		switch g.Role {
		case config.RoleOperator:
			return g.covers(scope)
		case config.RoleTrustedAutomation:
			return g.covers(scope) && g.coversPlatform(platform)
		}
		return false
	})
}

// Operator reports the operator role on scope, which lets its holder consent
// to a side that needs a decision only because the requester does not act
// for it (ADR-13 rule 6).
func (gs Grants) Operator(scope string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool { return g.Role == config.RoleOperator && g.covers(scope) })
}

// CanApprove reports whether the principal is an approver of scope. Four-eyes
// and distinct approvers are checked by the change requests.
func (gs Grants) CanApprove(scope string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool { return g.Role == config.RoleApprover && g.covers(scope) })
}

// Delegates returns the trusted_automation grant that decides sides in scope
// for platform by delegation (ADR-11), or nil.
func (gs Grants) Delegates(scope, platform string) *Grant {
	for i := range gs {
		if g := &gs[i]; g.Role == config.RoleTrustedAutomation && g.covers(scope) && g.coversPlatform(platform) {
			return g
		}
	}
	return nil
}

// BreakGlass reports the break_glass role on scope (ADR-12).
func (gs Grants) BreakGlass(scope string) bool {
	return gs.has(func(g *Grant) bool { return g.Role == config.RoleBreakGlass && g.covers(scope) })
}
