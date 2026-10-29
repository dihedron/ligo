package bindings

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/jackc/pgx/v5"
)

// Revocation is the outcome of a bulk revocation for one binding: its
// change request, or why none was filed.
type Revocation struct {
	Binding string
	Request *changerequests.Request
	Error   error
}

// RevokeOn files the revocation of every binding of target whose source is
// source, or whose source scope matches sourceScope (containment, §7.2.3):
// one DELETE with consent ANY each, with the caller's sides, for an
// operator of the target's or the platform's scope. The comment is kept in
// each request's automation context.
func (s *Service) RevokeOn(ctx context.Context, c changerequests.Caller, target, source, sourceScope, comment, approvalReference string) ([]Revocation, error) {
	if (source == "") == (sourceScope == "") {
		return nil, invalid("give either source or sourceScope")
	}
	if comment == "" {
		return nil, invalid("comment is required")
	}
	if sourceScope != "" && !governance.ValidScopePattern(sourceScope) {
		return nil, invalid("sourceScope %q is not a scope pattern", sourceScope)
	}
	var scope, platformScope string
	err := s.DB.QueryRow(ctx, "SELECT scope, platform_scope FROM targets WHERE name = $1 AND state <> 'RETIRED'", target).Scan(&scope, &platformScope)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Grants.Sees(scope, platformScope) {
		return nil, refuse(404, "not-found", "target %q", target)
	}
	if err != nil {
		return nil, err
	}
	if !c.Grants.Operator(scope) && !c.Grants.Operator(platformScope) {
		return nil, refuse(403, "forbidden", "%s is no operator of %s or %s", c.ID(), scope, platformScope)
	}
	rows, err := s.DB.Query(ctx, `SELECT b.name, b.revision, b.source_scope FROM bindings b JOIN sources src ON src.id = b.source_id
		JOIN targets t ON t.id = b.target_id WHERE t.name = $1 AND t.state <> 'RETIRED' AND b.phase NOT IN ('DELETING', 'DELETE_FAILED')
		AND ($2 = '' OR src.name = $2) ORDER BY b.name`, target, source)
	if err != nil {
		return nil, err
	}
	type match struct {
		name, scope string
		revision    int64
	}
	matches, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (match, error) {
		var m match
		return m, r.Scan(&m.name, &m.revision, &m.scope)
	})
	if err != nil {
		return nil, err
	}
	automation, _ := json.Marshal(map[string]string{"bulkRevocation": target, "comment": comment})
	var out []Revocation
	for _, m := range matches {
		if sourceScope != "" && !governance.ScopeMatches(sourceScope, m.scope) {
			continue
		}
		r, err := s.Delete(ctx, c, m.name, m.revision, approvalReference, automation)
		out = append(out, Revocation{Binding: m.name, Request: r, Error: err})
	}
	return out, nil
}
