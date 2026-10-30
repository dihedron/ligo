package adminhttp

import (
	"net/http"

	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/targets"
)

func (s *Server) catalogRoutes(mux *router) {
	mux.HandleFunc("GET /v1/admin/catalog/targets", s.catalogTargets)
	mux.HandleFunc("GET /v1/admin/catalog/targets/{name}", s.catalogTarget)
	mux.HandleFunc("GET /v1/admin/catalog/targets/{name}/flows", s.catalogFlows)
	mux.HandleFunc("GET /v1/admin/catalog/sources", s.catalogSources)
}

// catalogTargets is the catalog search (§7.2.4); state is ACTIVE, or
// DEPRECATED to include deprecated targets.
func (s *Server) catalogTargets(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !viewer(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	var cursor struct {
		AfterName string `json:"afterName"`
	}
	size, err := page(r, &cursor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	list, err := s.Catalog.Targets(r.Context(), c, catalog.Query{Q: q.Get("q"), Platform: q.Get("platform"),
		PlatformType: q.Get("platformType"), Scope: q.Get("scope"), Label: q.Get("label"), ForSource: q.Get("forSource"),
		Deprecated: q.Get("state") == "DEPRECATED", AfterName: cursor.AfterName, Limit: size + 1})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	more := len(list) > size
	if more {
		list = list[:size]
		cursor.AfterName = list[size-1].Name
	}
	if list == nil {
		list = []catalog.Target{}
	}
	reply(w, http.StatusOK, map[string]any{"items": list, "nextPageToken": token(more, cursor)})
}

// catalogTarget: the target with its access levels and flows, and the
// governance outcome for each of the caller's sources.
func (s *Server) catalogTarget(w http.ResponseWriter, r *http.Request) {
	v, err := s.Targets.Get(r.Context(), caller(r), r.PathValue("name"))
	var outcomes []catalog.Outcome
	if err == nil {
		outcomes, err = s.Catalog.Outcomes(r.Context(), caller(r), v.Metadata.Name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if outcomes == nil {
		outcomes = []catalog.Outcome{}
	}
	reply(w, http.StatusOK, struct {
		*targets.View
		Outcomes []catalog.Outcome `json:"outcomes"`
	}{v, outcomes})
}

// catalogFlows: the target's effective flows without a secret store
// (§3.6), before any binding exists.
func (s *Server) catalogFlows(w http.ResponseWriter, r *http.Request) {
	v, err := s.Targets.Get(r.Context(), caller(r), r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, rules := v.Metadata, s.Bindings.Rules
	reply(w, http.StatusOK, map[string]any{"target": m.Name,
		"networkFlows": flows.Effective(m.Name, v.NetworkFlows, m.Platform, rules.PlatformFlows[m.Platform], "", nil, rules.Ligo)})
}

// catalogSources: the sources visible to the caller beyond their own.
func (s *Server) catalogSources(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !viewer(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	var cursor struct {
		AfterName string `json:"afterName"`
	}
	size, err := page(r, &cursor)
	var list []catalog.Source
	if err == nil {
		list, err = s.Catalog.Sources(r.Context(), c, cursor.AfterName, size+1)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	more := len(list) > size
	if more {
		list = list[:size]
		cursor.AfterName = list[size-1].Name
	}
	if list == nil {
		list = []catalog.Source{}
	}
	reply(w, http.StatusOK, map[string]any{"items": list, "nextPageToken": token(more, cursor)})
}
