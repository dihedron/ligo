package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/targets"
)

// SourcesPage is the sources list's data.
type SourcesPage struct {
	Filter  sources.Filter
	Sources []*sources.View
	Next    string
}

func (s *Server) sourceList(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	q := r.URL.Query()
	f := sources.Filter{Q: q.Get("q"), Scope: q.Get("scope"), State: q.Get("state"), TrustDomain: q.Get("trustDomain"), After: q.Get("after"),
		Limit: pageSize}
	list, more, err := s.Sources.List(r.Context(), session(r).Caller(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := SourcesPage{Filter: f, Sources: list}
	if more {
		d.Next = list[len(list)-1].Metadata.Name
	}
	p := s.frame(r, "Sources", "/ui/sources")
	p.Content = d
	s.page(w, r, http.StatusOK, "sources", p)
}

// SourcePage is a source's data: the source, its bindings and its trail.
type SourcePage struct {
	Source   *sources.View
	Bindings []*bindings.View
	Audit    []Entry
}

func (s *Server) source(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	ctx, c := r.Context(), session(r).Caller()
	v, err := s.Sources.Get(ctx, c, r.PathValue("name"))
	var d SourcePage
	if err == nil {
		d.Source = v
		d.Bindings, _, err = s.Bindings.List(ctx, c, bindings.Filter{Source: v.Metadata.Name, Limit: 200})
	}
	if err == nil {
		d.Audit, err = s.trail(ctx, "SOURCE", v.Metadata.Name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := s.frame(r, v.Metadata.Name, "/ui/sources")
	p.Content = d
	s.page(w, r, http.StatusOK, "source", p)
}

// TargetsPage is the targets list's data: the targets the user owns or
// administers.
type TargetsPage struct {
	Filter  targets.Filter
	Targets []*targets.View
	Next    string
}

func (s *Server) targetList(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	q := r.URL.Query()
	f := targets.Filter{Q: q.Get("q"), Platform: q.Get("platform"), Scope: q.Get("scope"), State: q.Get("state"), After: q.Get("after"),
		Limit: pageSize}
	list, more, err := s.Targets.List(r.Context(), session(r).Caller(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := TargetsPage{Filter: f, Targets: list}
	if more {
		d.Next = list[len(list)-1].Metadata.Name
	}
	p := s.frame(r, "Targets", "/ui/targets")
	p.Content = d
	s.page(w, r, http.StatusOK, "targets", p)
}

// TargetPage is a target's data: the target, who can reach it, and its
// trail.
type TargetPage struct {
	Target   *targets.View
	Bindings []*bindings.View
	Audit    []Entry
}

func (s *Server) target(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	ctx, c := r.Context(), session(r).Caller()
	v, err := s.Targets.Get(ctx, c, r.PathValue("name"))
	var d TargetPage
	if err == nil {
		d.Target = v
		d.Bindings, _, err = s.Bindings.List(ctx, c, bindings.Filter{Target: v.Metadata.Name, Limit: 200})
	}
	if err == nil {
		d.Audit, err = s.trail(ctx, "TARGET", v.Metadata.Name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := s.frame(r, v.Metadata.Name, "/ui/targets")
	p.Content = d
	s.page(w, r, http.StatusOK, "target", p)
}

// PlatformRow is a configured platform with its plugin's health.
type PlatformRow struct {
	Name, Type, Zone, Scope, DisplayName string
	TargetScopes                         []string
	IdentityProvider, SecretStore        string
	Serving                              bool
	Health                               string
}

// platforms lists server.yaml's platforms, read-only, with their health
// (§3.4); each plugin answers within 2s.
func (s *Server) platforms(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	var rows []PlatformRow
	for _, pp := range s.Config.PlatformProviders {
		for i := range pp.Platforms {
			pl := &pp.Platforms[i]
			row := PlatformRow{Name: pl.Name, Type: pp.Type, Zone: pl.Zone, Scope: pl.Scope, DisplayName: pl.DisplayName, TargetScopes: pl.TargetScopes,
				IdentityProvider: pl.IdentityProvider.Instance, SecretStore: pl.SecretStore.Instance}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			h, err := s.Plugins.Health(ctx, pl.Name) // shortcut: one platform after another; call in parallel if lists grow long
			cancel()
			switch {
			case err != nil:
				row.Health = "unreachable"
			case h.GetServing():
				row.Serving, row.Health = true, "serving"
			default:
				row.Health = h.GetPublicMessage()
			}
			rows = append(rows, row)
		}
	}
	p := s.frame(r, "Platforms", "/ui/platforms")
	p.Content = rows
	s.page(w, r, http.StatusOK, "platforms", p)
}

// CatalogPage is the catalog's data (§7.2.4).
type CatalogPage struct {
	Query   catalog.Query
	Types   []string
	Targets []catalog.Target
	Next    string
}

func (s *Server) catalogSearch(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	q := r.URL.Query()
	cq := catalog.Query{Q: q.Get("q"), PlatformType: q.Get("platformType"), Platform: q.Get("platform"), Scope: q.Get("scope"),
		Label: q.Get("label"), Deprecated: q.Get("deprecated") == "on", AfterName: q.Get("after"), Limit: pageSize + 1}
	list, err := s.Catalog.Targets(r.Context(), session(r).Caller(), cq)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := CatalogPage{Query: cq, Targets: list}
	if len(list) > pageSize {
		d.Targets = list[:pageSize]
		d.Next = d.Targets[pageSize-1].Name
	}
	seen := map[string]bool{}
	for _, pp := range s.Config.PlatformProviders {
		if !seen[pp.Type] {
			seen[pp.Type] = true
			d.Types = append(d.Types, pp.Type)
		}
	}
	p := s.frame(r, "Catalog", "/ui/catalog")
	p.Content = d
	s.page(w, r, http.StatusOK, "catalog", p)
}

// CardPage is a catalog target card: the target, its flows before any
// binding (no secret store), the same as JSON to copy, and the governance
// outcome for each of the user's sources.
type CardPage struct {
	Target    *targets.View
	Flows     []flows.Flow
	FlowsJSON string
	Outcomes  []catalog.Outcome
}

func (s *Server) catalogCard(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	ctx, c := r.Context(), session(r).Caller()
	v, err := s.Targets.Get(ctx, c, r.PathValue("target"))
	var d CardPage
	if err == nil {
		d.Target = v
		d.Outcomes, err = s.Catalog.Outcomes(ctx, c, v.Metadata.Name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, rules := v.Metadata, s.Bindings.Rules
	d.Flows = flows.Effective(m.Name, rules.Allow[m.Platform].Within(v.NetworkFlows), m.Platform, rules.PlatformFlows[m.Platform], "", nil, rules.Ligo)
	if b, err := json.MarshalIndent(map[string]any{"target": m.Name, "networkFlows": d.Flows}, "", "  "); err == nil {
		d.FlowsJSON = string(b)
	}
	p := s.frame(r, m.Name, "/ui/catalog")
	p.Content = d
	s.page(w, r, http.StatusOK, "catalog-card", p)
}
