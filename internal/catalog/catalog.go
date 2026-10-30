// Package catalog reads sources, targets and bindings as the caller may
// see them (§7.2.4): visibility by role and by the resources' visibility,
// the catalog of targets a caller could request, and the governance
// outcome of a target for the caller's sources (ADR-14 rule 7).
package catalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reader reads the catalog.
type Reader struct {
	DB     *pgxpool.Pool // the app pool: ligo_reader only reads the workload views (§4.1)
	Policy *governance.Policy
}

func notFound(format string, args ...any) error {
	return &changerequests.Error{Status: 404, Slug: "not-found", Detail: fmt.Sprintf(format, args...)}
}

// Target is a target as the catalog shows it.
type Target struct {
	Name          string            `json:"name"`
	Scope         string            `json:"scope"`
	Platform      string            `json:"platform"`
	PlatformType  string            `json:"platformType"`
	PlatformScope string            `json:"platformScope"`
	State         string            `json:"state"`
	DisplayName   string            `json:"displayName,omitempty"`
	Description   string            `json:"description,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Bound         bool              `json:"bound,omitempty"` // to Query.ForSource
	visibility    string
	visibleTo     []string
}

const targetColumns = `name, scope, platform, platform_type, platform_scope, state, coalesce(display_name, ''), coalesce(description, ''),
	labels, visibility, visible_to`

func scanTarget(row pgx.Row, extra ...any) (Target, error) {
	var t Target
	err := row.Scan(append([]any{&t.Name, &t.Scope, &t.Platform, &t.PlatformType, &t.PlatformScope, &t.State, &t.DisplayName,
		&t.Description, &t.Labels, &t.visibility, &t.visibleTo}, extra...)...)
	return t, err
}

func (t *Target) visible(c changerequests.Caller) bool {
	return c.Grants.Visible([]string{t.Scope, t.PlatformScope}, t.visibility, t.visibleTo)
}

// Target reads a non-retired target the caller can see (404 otherwise).
func (r *Reader) Target(ctx context.Context, c changerequests.Caller, name string) (*Target, error) {
	t, err := scanTarget(r.DB.QueryRow(ctx, "SELECT "+targetColumns+" FROM targets WHERE name = $1 AND state <> 'RETIRED'", name))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !t.visible(c) {
		return nil, notFound("target %q", name)
	}
	return &t, err
}

// Query filters the catalog of targets.
type Query struct {
	Q            string // in the name, display name, description or labels
	Platform     string
	PlatformType string
	Scope        string // a scope pattern the target scope matches
	Label        string // key=value
	ForSource    string // only targets the policy allows for this source, marked if bound to it
	Deprecated   bool   // DEPRECATED targets too
	AfterName    string // keyset pagination (§7.2.3)
	Limit        int    // default 50, at most 201
}

// Targets is the catalog (§7.2.4): the visible ACTIVE (and, on request,
// DEPRECATED) targets that the interconnection policy allows for a scope
// in which the caller is operator or trusted_automation, sorted by name.
// The owners of a target, on its scope or its platform's, see it anyway,
// except with ForSource, which keeps only what the policy allows for that
// source (an ACTIVE source the caller sees; 404 otherwise).
func (r *Reader) Targets(ctx context.Context, c changerequests.Caller, q Query) ([]Target, error) {
	limit := q.Limit
	switch {
	case limit <= 0:
		limit = 50
	case limit > 201: // 200 and one more, which tells the caller a next page exists
		limit = 201
	}
	states := []string{"ACTIVE"}
	if q.Deprecated {
		states = append(states, "DEPRECATED")
	}
	var sourceID *uuid.UUID
	var sourceScope string
	if q.ForSource != "" {
		var id uuid.UUID
		var vis string
		var visibleTo []string
		err := r.DB.QueryRow(ctx, "SELECT id, scope, visibility, visible_to FROM sources WHERE name = $1 AND state = 'ACTIVE'", q.ForSource).
			Scan(&id, &sourceScope, &vis, &visibleTo)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Grants.Visible([]string{sourceScope}, vis, visibleTo) {
			return nil, notFound("source %q", q.ForSource)
		}
		if err != nil {
			return nil, err
		}
		sourceID = &id
	}
	key, value, _ := strings.Cut(q.Label, "=")
	rows, err := r.DB.Query(ctx, "SELECT "+targetColumns+`,
			EXISTS (SELECT 1 FROM bindings b WHERE b.target_id = targets.id AND b.source_id = $7) FROM targets
		WHERE state = ANY($1) AND name > $2 AND ($3 = '' OR name ILIKE '%' || $3 || '%' OR display_name ILIKE '%' || $3 || '%'
			OR description ILIKE '%' || $3 || '%' OR labels::text ILIKE '%' || $3 || '%')
			AND ($4 = '' OR platform = $4) AND ($5 = '' OR platform_type = $5) AND ($6 = '' OR labels ->> $6 = $8)
		ORDER BY name`, states, q.AfterName, q.Q, q.Platform, q.PlatformType, key, sourceID, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() && len(out) < limit {
		var bound bool
		t, err := scanTarget(rows, &bound)
		if err != nil {
			return nil, err
		}
		switch {
		case !t.visible(c) || q.Scope != "" && !governance.ScopeMatches(q.Scope, t.Scope):
		case sourceID != nil:
			if sourceScope == t.Scope || r.Policy.Evaluate(sourceScope, t.Scope).Allowed {
				t.Bound = bound
				out = append(out, t)
			}
		case c.Grants.Sees(t.Scope, t.PlatformScope) || r.requestable(c, t.Scope):
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

// requestable reports whether the policy allows targetScope for a scope in
// which the caller can file a binding.
// shortcut: a grant's pattern stands for its base scope ("cloud/fin-01/*"
// for cloud/fin-01); rules that differ below a pattern's base are not seen,
// upgrade when the catalog must enumerate the caller's sources' scopes.
func (r *Reader) requestable(c changerequests.Caller, targetScope string) bool {
	for _, g := range c.Grants {
		if g.Role != config.RoleOperator && g.Role != config.RoleTrustedAutomation && g.Role != config.RoleFullAccess {
			continue
		}
		for _, p := range g.Scopes {
			if s := strings.TrimSuffix(p, "/*"); s == targetScope || p == "*" || r.Policy.Evaluate(s, targetScope).Allowed {
				return true
			}
		}
	}
	return false
}

// Outcome is the governance outcome of a target for one of the caller's
// sources: allowed with the sides a binding would need, or denied.
type Outcome struct {
	Source      string   `json:"source"`
	SourceScope string   `json:"sourceScope"`
	Allowed     bool     `json:"allowed"`
	Rule        string   `json:"rule,omitempty"`  // the deciding rule, "default", or "" for the same scope
	Sides       []string `json:"sides,omitempty"` // when allowed
}

// Outcomes evaluates a visible target against every source whose scope the
// caller acts for (§7.2.3, catalog view of a target).
func (r *Reader) Outcomes(ctx context.Context, c changerequests.Caller, target string) ([]Outcome, error) {
	t, err := r.Target(ctx, c, target)
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.Query(ctx, "SELECT name, scope FROM sources WHERE state = 'ACTIVE' ORDER BY name")
	if err != nil {
		return nil, err
	}
	sources, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) ([2]string, error) {
		var s [2]string
		err := row.Scan(&s[0], &s[1])
		return s, err
	})
	if err != nil {
		return nil, err
	}
	var out []Outcome
	for _, s := range sources {
		if !c.Grants.ActsFor(s[1], t.Platform) {
			continue
		}
		o := Outcome{Source: s[0], SourceScope: s[1], Allowed: true, Sides: []string{"TARGET"}}
		if s[1] != t.Scope {
			d := r.Policy.Evaluate(s[1], t.Scope)
			o.Allowed, o.Rule, o.Sides = d.Allowed, d.Rule, nil
			if d.Allowed {
				o.Sides = []string{"TARGET", "SOURCE"}
				for _, a := range d.AdditionalApprovals {
					o.Sides = append(o.Sides, "PARTY:"+a.Name)
				}
			}
		}
		out = append(out, o)
	}
	return out, nil
}

// Binding is a binding as its viewers see it.
type Binding struct {
	ID                                      uuid.UUID
	Name, Source, Target, AccessLevel       string
	SourceScope, TargetScope, PlatformScope string
	PartyScopes                             []string
	Phase                                   string
	Revision                                int64
}

// Binding reads a binding visible to the caller: a role on any of its
// three scopes, or on the scope of one of its additional parties, taken
// from the sides of its change requests (§7.2.4).
func (r *Reader) Binding(ctx context.Context, c changerequests.Caller, name string) (*Binding, error) {
	b := &Binding{Name: name}
	err := r.DB.QueryRow(ctx, `SELECT b.id, s.name, t.name, b.access_level, b.source_scope, b.target_scope, b.platform_scope, b.phase,
		b.revision, coalesce((SELECT array_agg(DISTINCT sd.scope) FROM change_requests cr
			JOIN change_request_sides sd ON sd.change_request_id = cr.id
			WHERE cr.resource_type = 'BINDING' AND cr.resource_id = b.id AND sd.side LIKE 'PARTY:%'), '{}')
		FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id WHERE b.name = $1`, name).
		Scan(&b.ID, &b.Source, &b.Target, &b.AccessLevel, &b.SourceScope, &b.TargetScope, &b.PlatformScope, &b.Phase, &b.Revision, &b.PartyScopes)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Grants.Sees(append([]string{b.SourceScope, b.TargetScope, b.PlatformScope}, b.PartyScopes...)...) {
		return nil, notFound("binding %q", name)
	}
	return b, err
}

// Source is a source as the catalog shows it to a target owner offering a
// binding.
type Source struct {
	Name        string `json:"name"`
	Scope       string `json:"scope"`
	TrustDomain string `json:"trustDomain"`
	DisplayName string `json:"displayName,omitempty"`
	Description string `json:"description,omitempty"`
}

// Sources are the ACTIVE sources visible to the caller beyond their own:
// LISTED or PUBLIC ones on scopes where the caller holds no role (§7.2.4),
// sorted by name after afterName.
func (r *Reader) Sources(ctx context.Context, c changerequests.Caller, afterName string, limit int) ([]Source, error) {
	rows, err := r.DB.Query(ctx, `SELECT name, scope, trust_domain, coalesce(display_name, ''), coalesce(description, ''), visibility,
		visible_to FROM sources WHERE state = 'ACTIVE' AND visibility <> 'PRIVATE' AND name > $1 ORDER BY name`, afterName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() && len(out) < limit {
		var s Source
		var vis string
		var visibleTo []string
		if err := rows.Scan(&s.Name, &s.Scope, &s.TrustDomain, &s.DisplayName, &s.Description, &vis, &visibleTo); err != nil {
			return nil, err
		}
		if !c.Grants.Sees(s.Scope) && c.Grants.Visible([]string{s.Scope}, vis, visibleTo) {
			out = append(out, s)
		}
	}
	return out, rows.Err()
}
