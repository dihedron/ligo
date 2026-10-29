package adminhttp

import (
	"encoding/json"
	"net/http"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/sources"
)

func (s *Server) sourceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/admin/sources", s.createSource)
	mux.HandleFunc("PUT /v1/admin/sources/{name}", s.updateSource)
	mux.HandleFunc("POST /v1/admin/sources/{name}/{op}", s.sourceState)
	mux.HandleFunc("GET /v1/admin/sources", s.listSources)
	mux.HandleFunc("GET /v1/admin/sources/{name}", s.getSource)
	mux.HandleFunc("POST /v1/admin/sources/test", s.testSource)
}

func (s *Server) createSource(w http.ResponseWriter, r *http.Request) {
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Sources.Create(r.Context(), caller(r), b)
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Sources.Get(r.Context(), caller(r), cr.ResourceName) })
}

func (s *Server) updateSource(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Sources.Update(r.Context(), caller(r), name, b)
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Sources.Get(r.Context(), caller(r), name) })
}

// stateChange is the body of a deprecate, reactivate or retire.
type stateChange struct {
	ExpectedRevision  *int64          `json:"expectedRevision"`
	ApprovalReference string          `json:"approvalReference"`
	AutomationContext json.RawMessage `json:"automationContext"`
}

func (b *stateChange) check() error {
	if b.ExpectedRevision == nil {
		return &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "expectedRevision is required"}
	}
	return nil
}

func (s *Server) sourceState(w http.ResponseWriter, r *http.Request) {
	name, op := r.PathValue("name"), r.PathValue("op")
	if op != "deprecate" && op != "reactivate" && op != "retire" {
		problem(w, http.StatusNotFound, "not-found", "no such operation")
		return
	}
	var b stateChange
	err := decode(r, &b)
	if err == nil {
		err = b.check()
	}
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Sources.SetState(r.Context(), caller(r), name, op, *b.ExpectedRevision, b.ApprovalReference, b.AutomationContext)
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Sources.Get(r.Context(), caller(r), name) })
}

func (s *Server) listSources(w http.ResponseWriter, r *http.Request) {
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
	list, more, err := s.Sources.List(r.Context(), c, sources.Filter{Scope: q.Get("scope"), TrustDomain: q.Get("trustDomain"),
		State: q.Get("state"), Label: q.Get("label"), Q: q.Get("q"), After: cursor.AfterName, Limit: size})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if more {
		cursor.AfterName = list[len(list)-1].Metadata.Name
	}
	if list == nil {
		list = []*sources.View{}
	}
	reply(w, http.StatusOK, map[string]any{"items": list, "nextPageToken": token(more, cursor)})
}

// getSource: the representation plus the last 20 audit entries.
func (s *Server) getSource(w http.ResponseWriter, r *http.Request) {
	v, err := s.Sources.Get(r.Context(), caller(r), r.PathValue("name"))
	var entries []auditDTO
	if err == nil {
		entries, _, err = s.auditPage(r.Context(), "SOURCE", v.Metadata.Name, nil, 20)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, struct {
		*sources.View
		Audit []auditDTO `json:"audit"`
	}{v, entries})
}

func (s *Server) testSource(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !viewer(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	var req sources.TestRequest
	err := decode(r, &req)
	var res *sources.TestResult
	if err == nil {
		res, err = s.Sources.Test(r.Context(), c, req)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, res)
}
