// Package changerequests records desired-state changes as change requests
// and decides them (ADR-09, ADR-11, ADR-13): the sides whose consent a
// request needs, how each is decided, four-eyes, and the apply once the
// consent rule is satisfied. Each resource type plugs in its own
// re-validation and apply (§6.2).
package changerequests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/jcs"
)

// Consent rules (ADR-13 rule 4).
const (
	ConsentAll = "ALL"
	ConsentAny = "ANY"
)

// Bases: how a side is decided, fixed at creation (ADR-13 rule 6).
const (
	BasisAuto      = "AUTO"
	BasisDelegated = "DELEGATED"
	BasisHuman     = "HUMAN"
)

// Side decisions.
const (
	Approved = "APPROVED"
	Declined = "DECLINED"
)

// The system identities that decide sides at creation.
const (
	AutoApprover      = "system:auto-approve"
	DelegatedApprover = "system:delegated-approval"
)

// Error is a refusal with the problem slug and HTTP status of §7.2.3.
type Error struct {
	Status int
	Slug   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Slug
	}
	return e.Slug + ": " + e.Detail
}

func refuse(status int, slug, format string, args ...any) *Error {
	return &Error{Status: status, Slug: slug, Detail: fmt.Sprintf(format, args...)}
}

// Caller is an authenticated principal with its grants.
type Caller struct {
	Principal authz.Principal
	Grants    authz.Grants
}

// ID is the caller's identity in change requests: its SPIFFE ID, or its
// user name.
func (c Caller) ID() string {
	if c.Principal.SPIFFEID != "" {
		return c.Principal.SPIFFEID
	}
	return c.Principal.Name
}

// Request is a change request (change_requests, §4.2) with its sides.
type Request struct {
	ID                uuid.UUID
	ResourceType      string // SOURCE, TARGET, BINDING
	ResourceName      string
	ResourceID        *uuid.UUID
	Operation         string // CREATE, UPDATE, DELETE
	Consent           string
	Zone              string // TARGET, BINDING
	OwnerScope        string // SOURCE, TARGET
	SourceScope       string // BINDING
	TargetScope       string // BINDING
	PlatformScope     string // TARGET, BINDING
	ExpectedRevision  *int64 // UPDATE, DELETE
	Payload           json.RawMessage
	PayloadSHA256     string
	ApprovalReference string
	AutomationContext json.RawMessage
	PolicySHA256      string
	DistinctApprovers bool
	Status            string
	RequestedBy       string
	ExpiresAt         time.Time
	Sides             []Side
}

// scopes are every scope of the request and its sides, for visibility.
func (r *Request) scopes() []string {
	var out []string
	for _, s := range []string{r.OwnerScope, r.SourceScope, r.TargetScope, r.PlatformScope} {
		if s != "" {
			out = append(out, s)
		}
	}
	for _, s := range r.Sides {
		out = append(out, s.Scope)
	}
	return out
}

// Side is a side of a change request (change_request_sides, §4.2).
type Side struct {
	Name             string // OWNER, SOURCE, TARGET, PLATFORM, PARTY:<name>
	Scope            string
	ApprovalRequired bool
	Basis            string
	Decision         string // "", APPROVED, DECLINED
	DecidedBy        string
}

// Candidate is a side a request needs, before its basis is known; Platform
// is the platform of a target or binding, for delegation (ADR-11).
type Candidate struct {
	Side     string
	Scope    string
	Platform string
}

// BuildSides decides how each side is decided, once, at creation (§7.2.3
// "Sides at creation", rules 2 and 3): AUTO when the caller acts for a side
// whose scope does not require approval, DELEGATED when a trusted_automation
// SPIFFE principal covers it, HUMAN otherwise. A delegated side needs the
// approval reference, matching the delegation's pattern if it has one.
func BuildSides(candidates []Candidate, c Caller, p *governance.Policy, approvalReference string) ([]Side, error) {
	var sides []Side
	for _, cand := range candidates {
		s := Side{Name: cand.Side, Scope: cand.Scope, Basis: BasisHuman, ApprovalRequired: true}
		if c.Grants.ActsFor(cand.Scope, cand.Platform) && !p.ApprovalRequired(cand.Scope) {
			s.Basis, s.ApprovalRequired, s.Decision, s.DecidedBy = BasisAuto, false, Approved, AutoApprover
		} else if g := c.Grants.Delegates(cand.Scope, cand.Platform); g != nil && c.Principal.SPIFFEID != "" {
			if approvalReference == "" {
				return nil, refuse(422, "validation-failed", "side %s is approved by delegation: approvalReference is required", cand.Side)
			}
			if g.ApprovalReference != nil && !g.ApprovalReference.MatchString(approvalReference) {
				return nil, refuse(422, "validation-failed", "approvalReference %q does not match the delegation's approval_reference_pattern", approvalReference)
			}
			s.Basis, s.Decision, s.DecidedBy = BasisDelegated, Approved, DelegatedApprover
		}
		sides = append(sides, s)
	}
	return sides, nil
}

// Complete reports whether the consent rule is satisfied.
func Complete(consent string, sides []Side) bool {
	n := count(sides, Approved)
	if consent == ConsentAny {
		return n > 0
	}
	return n == len(sides)
}

// Rejected reports whether the request is rejected: ALL on one decline, ANY
// only when every side declined.
func Rejected(consent string, sides []Side) bool {
	n := count(sides, Declined)
	if consent == ConsentAny {
		return n == len(sides)
	}
	return n > 0
}

func count(sides []Side, decision string) int {
	n := 0
	for _, s := range sides {
		if s.Decision == decision {
			n++
		}
	}
	return n
}

// SelectSides returns the sides the caller decides (§7.2.3 "Deciding
// sides", rules 1 to 3): the pending HUMAN sides it is an approver for, or
// an operator for where approval is not required (never a party's), never
// as the requester; one per person when distinct approvers are required.
func SelectSides(r *Request, c Caller, p *governance.Policy, approve bool, side string) ([]string, error) {
	if c.ID() == r.RequestedBy {
		return nil, refuse(403, "four-eyes-violation", "the requester cannot decide its own change request")
	}
	var eligible []string
	for _, s := range r.Sides {
		if s.Basis != BasisHuman || s.Decision != "" {
			continue
		}
		operator := !p.ApprovalRequired(s.Scope) && !strings.HasPrefix(s.Name, "PARTY:") && c.Grants.Operator(s.Scope)
		if c.Grants.CanApprove(s.Scope) || operator {
			eligible = append(eligible, s.Name)
		}
	}
	if len(eligible) == 0 {
		return nil, refuse(403, "forbidden", "no pending side of this change request can be decided by %s", c.ID())
	}
	if approve && r.DistinctApprovers && slices.ContainsFunc(r.Sides, func(s Side) bool { return s.Decision == Approved && s.DecidedBy == c.ID() }) {
		return nil, refuse(403, "distinct-approver-required", "%s already approved another side of this change request", c.ID())
	}
	switch {
	case side != "" && !slices.Contains(eligible, side):
		return nil, refuse(403, "forbidden", "side %s cannot be decided by %s", side, c.ID())
	case side != "":
		return []string{side}, nil
	case approve && r.DistinctApprovers && len(eligible) > 1:
		return nil, refuse(400, "side-required", "choose one of the sides %v", eligible)
	}
	return eligible, nil
}

// Hash is the hex SHA-256 of the JCS form of a payload (§7.2.3).
func Hash(payload json.RawMessage) (string, error) {
	canonical, err := jcs.Transform(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
