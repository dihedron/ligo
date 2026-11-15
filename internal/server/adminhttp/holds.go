package adminhttp

import (
	"net/http"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
)

func (s *Server) holdRoutes(mux *router) {
	mux.HandleFunc("GET /v1/admin/holds", s.listHolds)
	mux.HandleFunc("POST /v1/admin/holds/{id}/lift", s.liftHold)
	mux.HandleFunc("POST /v1/admin/sources/{name}/release", s.release)
	mux.HandleFunc("POST /v1/admin/targets/{name}/release", s.release)
	mux.HandleFunc("POST /v1/admin/bindings/{name}/release", s.release)
}

func (s *Server) listHolds(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !viewer(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	var cursor struct {
		AfterID string `json:"afterId"`
	}
	size, err := page(r, &cursor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	list, more, err := s.Bindings.ListHolds(r.Context(), c, bindings.HoldFilter{Binding: q.Get("binding"), All: q.Get("state") == "all",
		After: cursor.AfterID, Limit: size})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if more {
		cursor.AfterID = list[len(list)-1].ID.String()
	}
	if list == nil {
		list = []bindings.Hold{}
	}
	reply(w, http.StatusOK, map[string]any{"items": list, "nextPageToken": token(more, cursor)})
}

// liftBody is the body of a lift.
type liftBody struct {
	Comment string `json:"comment"`
}

func (s *Server) liftHold(w http.ResponseWriter, r *http.Request) {
	var b liftBody
	err := decode(r, &b)
	if err == nil {
		err = s.Bindings.LiftHold(r.Context(), caller(r), r.PathValue("id"), b.Comment)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// releaseBody is the body of a release by an administrator.
type releaseBody struct {
	ExpectedRevision *int64 `json:"expectedRevision"`
	Justification    string `json:"justification"`
}

// release files the release of a managed resource by an administrator
// (.specs/ligo-managed-resources.md §3.3).
func (s *Server) release(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var b releaseBody
	err := decode(r, &b)
	if err == nil && b.ExpectedRevision == nil {
		err = &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "expectedRevision is required"}
	}
	var cr *changerequests.Request
	if err == nil {
		c, rev := caller(r), *b.ExpectedRevision
		switch r.Pattern {
		case "POST /v1/admin/sources/{name}/release":
			cr, err = s.Sources.Release(r.Context(), c, name, rev, b.Justification)
		case "POST /v1/admin/targets/{name}/release":
			cr, err = s.Targets.Release(r.Context(), c, name, rev, b.Justification)
		default:
			cr, err = s.Bindings.Release(r.Context(), c, name, rev, b.Justification)
		}
	}
	s.filed(w, r, cr, err, nil)
}
