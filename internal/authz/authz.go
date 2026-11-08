// Package authz maps principals to the roles of their authorization
// bindings, on jurisdictions (§7.2.2).
package authz

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/config"
)

// Principal is an authenticated caller: a SPIFFE ID (mTLS) or an LDAP user
// with the DNs of its groups.
type Principal struct {
	Name     string
	SPIFFEID string
	Groups   []string
	// AccountGroups are the DNs of the groups a user is a direct member of under
	// ldap_groups.search_base, sorted; also in Groups, for the audit trail.
	AccountGroups []string
	// DisplayName is a person's full name from the directory, for the UI.
	DisplayName string
}

// Grant is an authorization binding that applies to a principal.
type Grant struct {
	Role          string
	Jurisdictions []string
	Platforms     []string
	// ApprovalReference is the compiled approval_reference_pattern, or nil.
	ApprovalReference *regexp.Regexp
	RateLimit         *config.APIRateLimit
}

func (g *Grant) covers(jurisdiction string) bool {
	return slices.ContainsFunc(g.Jurisdictions, func(p string) bool { return charter.JurisdictionMatches(p, jurisdiction) })
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
	rules    *charter.GroupRules
	active   func(account string) bool
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
		g := Grant{Role: b.Role, Jurisdictions: b.Jurisdictions, Platforms: b.Platforms, RateLimit: b.RateLimit}
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

// UseAccounts adds the roles derived from directory groups, while active says
// their account is registered and ACTIVE (.specs/ligo-tenancy.md §8). Call it
// before serving.
func (a *Authorizer) UseAccounts(rules *charter.GroupRules, active func(account string) bool) {
	a.rules, a.active = rules, active
}

// For returns the grants of p: by SPIFFE ID for a SPIFFE principal, by group
// DN (ignoring case) for an LDAP one, never both, with the roles its account
// groups derive.
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
	if p.SPIFFEID != "" {
		return out
	}
	for _, dn := range p.AccountGroups {
		for _, m := range a.rules.Match(dn) {
			if a.active(m.Account) {
				out = append(out, Grant{Role: m.Role, Jurisdictions: []string{m.Jurisdiction}})
			}
		}
	}
	return out
}

// Grants are the effective grants of a principal: the union of its bindings.
type Grants []Grant

// reads reports whether a role lets its holder read resources: account_admin
// manages the registry only, and break_glass alone reads nothing (§7.2.2).
func (g *Grant) reads() bool {
	return g.Role != config.RoleBreakGlass && g.Role != config.RoleAccountAdmin
}

// Viewer reports whether the grants may read: any role but break_glass or
// account_admin alone (§7.2.2).
func (gs Grants) Viewer() bool {
	return gs.has((*Grant).reads)
}

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

// AccountAdmin reports whether the principal may change the account registry.
func (gs Grants) AccountAdmin() bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool { return g.Role == config.RoleAccountAdmin })
}

// InJurisdictions reports whether a role that reads reaches anywhere in pattern.
func (gs Grants) InJurisdictions(pattern string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool {
		return g.reads() && slices.ContainsFunc(g.Jurisdictions, func(s string) bool { return charter.PatternsOverlap(s, pattern) })
	})
}

// Sees reports whether any role other than break_glass covers one of the
// jurisdictions of a resource (its jurisdiction; a target's platform jurisdiction; a binding's
// three jurisdictions and its parties').
func (gs Grants) Sees(jurisdictions ...string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool {
		return g.Role != config.RoleBreakGlass && slices.ContainsFunc(jurisdictions, g.covers)
	})
}

// ActsFor reports whether the principal holds operator rights on jurisdiction: as
// operator, or as trusted_automation covering jurisdiction and platform.
func (gs Grants) ActsFor(jurisdiction, platform string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool {
		switch g.Role {
		case config.RoleOperator:
			return g.covers(jurisdiction)
		case config.RoleTrustedAutomation:
			return g.covers(jurisdiction) && g.coversPlatform(platform)
		}
		return false
	})
}

// Visible reports whether a source or target with these jurisdictions (a
// target's: its own and its platform's) and visibility is visible: through
// a role on its jurisdictions or, beyond them, LISTED to roles on a jurisdiction matching
// visibleTo and PUBLIC to any role (§7.2.4).
func (gs Grants) Visible(jurisdictions []string, mode string, visibleTo []string) bool {
	if gs.Sees(jurisdictions...) {
		return true
	}
	return gs.has(func(g *Grant) bool {
		if !g.reads() {
			return false
		}
		return mode == "PUBLIC" || mode == "LISTED" && slices.ContainsFunc(g.Jurisdictions, func(s string) bool {
			return slices.ContainsFunc(visibleTo, func(v string) bool { return charter.PatternsOverlap(s, v) })
		})
	})
}

// Operator reports the operator role on jurisdiction, which lets its holder consent
// to a side that needs a decision only because the requester does not act
// for it (ADR-13 rule 6).
func (gs Grants) Operator(jurisdiction string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool { return g.Role == config.RoleOperator && g.covers(jurisdiction) })
}

// CanApprove reports whether the principal is an approver of jurisdiction. Four-eyes
// and distinct approvers are checked by the change requests.
func (gs Grants) CanApprove(jurisdiction string) bool {
	return gs.FullAccess() || gs.has(func(g *Grant) bool { return g.Role == config.RoleApprover && g.covers(jurisdiction) })
}

// Delegates returns the trusted_automation grant that decides sides in jurisdiction
// for platform by delegation (ADR-11), or nil.
func (gs Grants) Delegates(jurisdiction, platform string) *Grant {
	for i := range gs {
		if g := &gs[i]; g.Role == config.RoleTrustedAutomation && g.covers(jurisdiction) && g.coversPlatform(platform) {
			return g
		}
	}
	return nil
}

// BreakGlass reports the break_glass role on jurisdiction (ADR-12).
func (gs Grants) BreakGlass(jurisdiction string) bool {
	return gs.has(func(g *Grant) bool { return g.Role == config.RoleBreakGlass && g.covers(jurisdiction) })
}
