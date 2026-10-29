package sources

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/jackc/pgx/v5"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// APIVersion of the resource representations (§3).
const APIVersion = "ligo.dihedron.org/v1alpha1"

// View is the representation of a source (§3.2).
type View struct {
	APIVersion string `json:"apiVersion"`
	Source
	Metadata ViewMetadata `json:"metadata"`
	Status   struct {
		Bindings int `json:"bindings"` // visible to the caller
	} `json:"status"`
}

type ViewMetadata struct {
	ID                     uuid.UUID  `json:"id"`
	Name                   string     `json:"name"`
	Scope                  string     `json:"scope"`
	State                  string     `json:"state"`
	Revision               int64      `json:"revision"`
	CreatedAt              time.Time  `json:"createdAt"`
	UpdatedAt              time.Time  `json:"updatedAt"`
	CreatedBy              string     `json:"createdBy"`
	UpdatedBy              string     `json:"updatedBy"`
	PendingChangeRequestID *uuid.UUID `json:"pendingChangeRequestId"`
}

const viewColumns = columns + `, created_at, updated_at, created_by, updated_by,
	(SELECT c.id FROM change_requests c WHERE c.resource_type = 'SOURCE' AND c.resource_name = sources.name AND c.status = 'PENDING')`

func scanView(row pgx.Row) (*View, *stored, error) {
	v := &View{APIVersion: APIVersion}
	m := &v.Metadata
	st := &stored{}
	st.Kind = "Source"
	err := row.Scan(&st.ID, &st.Revision, &st.Metadata.Name, &st.Metadata.Scope, &st.Metadata.State, &st.Identity.TrustDomain,
		&st.Identity.SVIDRegex, &st.Identity.SampleSPIFFEIDs, &st.DisplayName, &st.Description, &st.Labels, &st.ExternalRefs,
		&st.Contacts, &st.Visibility.Mode, &st.Visibility.VisibleTo, &m.CreatedAt, &m.UpdatedAt, &m.CreatedBy, &m.UpdatedBy,
		&m.PendingChangeRequestID)
	if len(st.Visibility.VisibleTo) == 0 {
		st.Visibility.VisibleTo = nil
	}
	v.Source = st.Source
	m.ID, m.Name, m.Scope, m.State, m.Revision = st.ID, st.Metadata.Name, st.Metadata.Scope, st.Metadata.State, st.Revision
	return v, st, err
}

func visible(c changerequests.Caller, st *stored) bool {
	return c.Grants.Visible([]string{st.Metadata.Scope}, st.Visibility.Mode, st.Visibility.VisibleTo)
}

// Get returns the non-retired source called name, if the caller sees it
// (404 otherwise).
func (s *Service) Get(ctx context.Context, c changerequests.Caller, name string) (*View, error) {
	v, st, err := scanView(s.DB.QueryRow(ctx, "SELECT "+viewColumns+" FROM sources WHERE name = $1 AND state <> 'RETIRED'", name))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !visible(c, st) {
		return nil, refuse(404, "not-found", "source %q", name)
	}
	if err != nil {
		return nil, err
	}
	return v, s.countBindings(ctx, c, v)
}

// countBindings sets the number of the source's bindings the caller sees.
func (s *Service) countBindings(ctx context.Context, c changerequests.Caller, v *View) error {
	rows, err := s.DB.Query(ctx, "SELECT ARRAY[source_scope, target_scope, platform_scope] FROM bindings WHERE source_id = $1", v.Metadata.ID)
	if err != nil {
		return err
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[[]string])
	for _, sc := range scopes {
		if c.Grants.Sees(sc...) {
			v.Status.Bindings++
		}
	}
	return err
}

// Filter selects sources (GET /v1/admin/sources).
type Filter struct {
	Scope       string // a scope pattern
	TrustDomain string
	State       string // default: every state but RETIRED
	Label       string // key=value
	Q           string // in the name or the display name
	After       string
	Limit       int
}

// List returns the sources the caller sees that f selects, by name, at
// most f.Limit, and whether more follow (keyset on name, §7.2.3).
func (s *Service) List(ctx context.Context, c changerequests.Caller, f Filter) ([]*View, bool, error) {
	key, value, _ := strings.Cut(f.Label, "=")
	var out []*View
	after := f.After
	for {
		rows, err := s.DB.Query(ctx, "SELECT "+viewColumns+` FROM sources WHERE name > $1
			AND ($2 = '' OR trust_domain = $2) AND (state::text = $3 OR $3 = '' AND state <> 'RETIRED')
			AND ($4 = '' OR labels ->> $4 = $5) AND ($6 = '' OR name ILIKE '%' || $6 || '%' OR display_name ILIKE '%' || $6 || '%')
			ORDER BY name LIMIT $7`, after, f.TrustDomain, f.State, key, value, f.Q, 2*f.Limit)
		if err != nil {
			return nil, false, err
		}
		var batch []*View
		read := 0
		for rows.Next() {
			v, st, err := scanView(rows)
			if err != nil {
				rows.Close()
				return nil, false, err
			}
			read++
			after = st.Metadata.Name
			if visible(c, st) && (f.Scope == "" || governance.ScopeMatches(f.Scope, st.Metadata.Scope)) {
				batch = append(batch, v)
			}
		}
		if err := rows.Err(); err != nil {
			return nil, false, err
		}
		for _, v := range batch {
			if len(out) == f.Limit {
				return out, true, nil
			}
			if err := s.countBindings(ctx, c, v); err != nil {
				return nil, false, err
			}
			out = append(out, v)
		}
		if read < 2*f.Limit {
			return out, false, nil
		}
	}
}

// TestRequest is the body of POST /v1/admin/sources/test.
type TestRequest struct {
	TrustDomain   string   `json:"trustDomain"`
	SVIDRegex     string   `json:"svidRegex"`
	SPIFFEIDs     []string `json:"spiffeIds"`
	CurrentSource string   `json:"currentSource"`
}

// TestResult is what the regex tester finds; nothing is stored.
type TestResult struct {
	Valid     bool            `json:"valid"`
	Error     string          `json:"error,omitempty"`
	Scope     string          `json:"scope,omitempty"`
	Matches   map[string]bool `json:"matches"`
	Narrowing *TestNarrowing  `json:"narrowing,omitempty"`
	Overlaps  []TestOverlap   `json:"overlaps"`
}

type TestNarrowing struct {
	Narrower       bool     `json:"narrower"`
	Undecided      bool     `json:"undecided,omitempty"`
	Witness        string   `json:"witness,omitempty"`
	DroppedSamples []string `json:"droppedSamples"`
}

type TestOverlap struct {
	Source    string `json:"source"`
	Witness   string `json:"witness,omitempty"` // an identity both match
	Undecided bool   `json:"undecided,omitempty"`
}

// Test runs the regex tester (§7.2.3): Appendix A, the scope, which IDs
// match, the narrowing of a current source, and the overlaps with the
// other sources of the scope the caller sees (T-34).
func (s *Service) Test(ctx context.Context, c changerequests.Caller, req TestRequest) (*TestResult, error) {
	res := &TestResult{Matches: map[string]bool{}, Overlaps: []TestOverlap{}}
	extractor, ok := s.Rules.Extractors[req.TrustDomain]
	if _, err := spiffeid.TrustDomainFromString(req.TrustDomain); err != nil || !ok {
		res.Error = "trustDomain " + req.TrustDomain + " is accepted by no platform"
		return res, nil
	}
	var re *regexp.Regexp
	var err error
	if re, err = regexpolicy.ValidateSVIDRegex(req.SVIDRegex, req.TrustDomain, s.Rules.Regex); err != nil {
		res.Error = err.Error()
		return res, nil
	}
	if res.Scope, err = extractor.SourceScope(req.SVIDRegex, req.TrustDomain); err != nil {
		res.Error = "the fixed beginning of the regex resolves to no scope (§3.9)"
		return res, nil
	}
	res.Valid = true
	for _, id := range req.SPIFFEIDs {
		parsed, err := spiffeid.FromString(id)
		res.Matches[id] = err == nil && parsed.TrustDomain().Name() == req.TrustDomain && re.MatchString(id)
	}
	limit := s.Rules.Regex.NarrowingStateLimit
	if req.CurrentSource != "" {
		cur, err := s.Get(ctx, c, req.CurrentSource)
		if err != nil {
			return nil, err
		}
		n, err := regexpolicy.CheckNarrowing(cur.Identity.SVIDRegex, req.SVIDRegex, limit)
		res.Narrowing = &TestNarrowing{Narrower: err == nil && n.Narrower, Undecided: err != nil, Witness: n.Witness, DroppedSamples: []string{}}
		for _, sample := range cur.Identity.SampleSPIFFEIDs {
			if !re.MatchString(sample) {
				res.Narrowing.DroppedSamples = append(res.Narrowing.DroppedSamples, sample)
			}
		}
	}
	rows, err := s.DB.Query(ctx, "SELECT "+columns+" FROM sources WHERE scope = $1 AND state <> 'RETIRED' AND name <> $2 ORDER BY name",
		res.Scope, req.CurrentSource)
	if err != nil {
		return nil, err
	}
	others, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*stored, error) { return scan(row) })
	if err != nil {
		return nil, err
	}
	for _, o := range slices.DeleteFunc(others, func(o *stored) bool { return !visible(c, o) }) {
		ov, err := regexpolicy.CheckOverlap(req.SVIDRegex, o.Identity.SVIDRegex, limit)
		if err != nil || ov.Overlaps {
			res.Overlaps = append(res.Overlaps, TestOverlap{Source: o.Metadata.Name, Witness: ov.Witness, Undecided: err != nil})
		}
	}
	return res, nil
}

// SourceDiff is how an update changes a source: the changed fields and,
// for a narrowed regex, the current samples it no longer matches.
type SourceDiff struct {
	Changes        []changerequests.Change `json:"changes"`
	DroppedSamples []string                `json:"droppedSamples,omitempty"`
}

// Diff compares an UPDATE's payload with the source's current revision.
func (s *Service) Diff(ctx context.Context, r *changerequests.Request) (any, error) {
	cur, err := s.loadID(ctx, s.DB, *r.ResourceID, false)
	if err != nil {
		return nil, err
	}
	old, err := json.Marshal(cur.Source)
	if err != nil {
		return nil, err
	}
	d := &SourceDiff{}
	if d.Changes, err = changerequests.Diff(old, r.Payload); err != nil {
		return nil, err
	}
	var proposed Source
	if err := json.Unmarshal(r.Payload, &proposed); err != nil {
		return nil, err
	}
	if proposed.Identity.SVIDRegex != cur.Identity.SVIDRegex {
		if re, err := regexp.Compile(proposed.Identity.SVIDRegex); err == nil {
			for _, sample := range cur.Identity.SampleSPIFFEIDs {
				if !re.MatchString(sample) {
					d.DroppedSamples = append(d.DroppedSamples, sample)
				}
			}
		}
	}
	return d, nil
}
