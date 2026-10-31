package targets

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/jackc/pgx/v5"
)

// View is the representation of a target (§3.3).
type View struct {
	APIVersion string `json:"apiVersion"`
	Target
	Metadata ViewMetadata `json:"metadata"`
	Status   struct {
		Bindings int `json:"bindings"` // visible to the caller
	} `json:"status"`
}

type ViewMetadata struct {
	ID                     uuid.UUID  `json:"id"`
	Name                   string     `json:"name"`
	Scope                  string     `json:"scope"`
	Platform               string     `json:"platform"`
	PlatformType           string     `json:"platformType"`
	PlatformScope          string     `json:"platformScope"`
	Zone                   string     `json:"zone"`
	State                  string     `json:"state"`
	Revision               int64      `json:"revision"`
	CreatedAt              time.Time  `json:"createdAt"`
	UpdatedAt              time.Time  `json:"updatedAt"`
	CreatedBy              string     `json:"createdBy"`
	UpdatedBy              string     `json:"updatedBy"`
	PendingChangeRequestID *uuid.UUID `json:"pendingChangeRequestId"`
}

// view completes a stored target with its metadata and the bindings the
// caller sees.
func (s *Service) view(ctx context.Context, c changerequests.Caller, st *stored) (*View, error) {
	m := st.Metadata
	v := &View{APIVersion: sources.APIVersion, Target: st.Target, Metadata: ViewMetadata{ID: st.ID, Name: m.Name, Scope: m.Scope,
		Platform: m.Platform, PlatformType: m.PlatformType, PlatformScope: m.PlatformScope, Zone: m.Zone, State: m.State, Revision: st.Revision}}
	vm := &v.Metadata
	err := s.DB.QueryRow(ctx, `SELECT created_at, updated_at, created_by, updated_by, (SELECT c.id FROM change_requests c
		WHERE c.resource_type = 'TARGET' AND c.resource_name = t.name AND c.status = 'PENDING') FROM targets t WHERE id = $1`,
		st.ID).Scan(&vm.CreatedAt, &vm.UpdatedAt, &vm.CreatedBy, &vm.UpdatedBy, &vm.PendingChangeRequestID)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(ctx, "SELECT ARRAY[source_scope, target_scope, platform_scope] FROM bindings WHERE target_id = $1", st.ID)
	if err != nil {
		return nil, err
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[[]string])
	for _, sc := range scopes {
		if c.Grants.Sees(sc...) {
			v.Status.Bindings++
		}
	}
	return v, err
}

// Get returns the non-retired target called name if the caller sees it:
// by its visibility, and always for the platform's owners (§3.3).
func (s *Service) Get(ctx context.Context, c changerequests.Caller, name string) (*View, error) {
	st, err := load(ctx, s.DB, "name = $1 AND state <> 'RETIRED'", name, false)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Grants.Sees(st.Metadata.PlatformScope) &&
		!c.Grants.Visible([]string{st.Metadata.Scope}, st.Visibility.Mode, st.Visibility.VisibleTo) {
		return nil, refuse(404, "not-found", "target %q", name)
	}
	if err != nil {
		return nil, err
	}
	return s.view(ctx, c, st)
}

// Filter selects targets (GET /v1/admin/targets).
type Filter struct {
	Q, Platform, PlatformType string
	Scope                     string // a scope pattern
	Label                     string // key=value
	State                     string // default: every state but RETIRED
	After                     string
	Limit                     int
}

// List returns the targets the caller owns or administers (a role on the
// target's or the platform's scope) that f selects, by name, at most
// f.Limit, and whether more follow (keyset on name, §7.2.3).
// shortcut: a target is read with its levels, flows and metadata (five queries), fine for admin pages of ≤ 200; join in SQL if lists get hot.
func (s *Service) List(ctx context.Context, c changerequests.Caller, f Filter) ([]*View, bool, error) {
	key, value, _ := strings.Cut(f.Label, "=")
	var out []*View
	after := f.After
	for {
		rows, err := s.DB.Query(ctx, `SELECT id FROM targets WHERE name > $1 AND ($2 = '' OR platform = $2)
			AND ($3 = '' OR platform_type = $3) AND (state::text = $4 OR $4 = '' AND state <> 'RETIRED')
			AND ($5 = '' OR labels ->> $5 = $6) AND ($7 = '' OR name ILIKE '%' || $7 || '%' OR display_name ILIKE '%' || $7 || '%')
			ORDER BY name LIMIT $8`, after, f.Platform, f.PlatformType, f.State, key, value, f.Q, 2*f.Limit)
		if err != nil {
			return nil, false, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return nil, false, err
		}
		for _, id := range ids {
			st, err := load(ctx, s.DB, "id = $1", id, false)
			if err != nil {
				return nil, false, err
			}
			after = st.Metadata.Name
			if !c.Grants.Sees(st.Metadata.Scope, st.Metadata.PlatformScope) || f.Scope != "" && !governance.ScopeMatches(f.Scope, st.Metadata.Scope) {
				continue
			}
			if len(out) == f.Limit {
				return out, true, nil
			}
			v, err := s.view(ctx, c, st)
			if err != nil {
				return nil, false, err
			}
			out = append(out, v)
		}
		if len(ids) < 2*f.Limit {
			return out, false, nil
		}
	}
}

// TargetDiff is how an update changes a target: the changed fields and,
// for narrowed levels, the privileges each one loses (§3.10).
type TargetDiff struct {
	Changes           []changerequests.Change `json:"changes"`
	RemovedPrivileges map[string][]string     `json:"removedPrivileges,omitempty"`
}

// Diff compares an UPDATE's payload with the target's current revision.
func (s *Service) Diff(ctx context.Context, r *changerequests.Request) (any, error) {
	cur, err := load(ctx, s.DB, "id = $1", *r.ResourceID, false)
	if err != nil {
		return nil, err
	}
	old, err := json.Marshal(cur.Target)
	if err != nil {
		return nil, err
	}
	d := &TargetDiff{}
	if d.Changes, err = changerequests.Diff(old, r.Payload); err != nil {
		return nil, err
	}
	var proposed Target
	if err := json.Unmarshal(r.Payload, &proposed); err != nil {
		return nil, err
	}
	for _, l := range cur.AccessLevels {
		i := slices.IndexFunc(proposed.AccessLevels, func(p AccessLevel) bool { return p.Name == l.Name })
		if i < 0 {
			continue
		}
		for _, p := range l.Privileges {
			if !slices.Contains(proposed.AccessLevels[i].Privileges, p) {
				if d.RemovedPrivileges == nil {
					d.RemovedPrivileges = map[string][]string{}
				}
				d.RemovedPrivileges[l.Name] = append(d.RemovedPrivileges[l.Name], p)
			}
		}
	}
	return d, nil
}
