package adminhttp

import (
	"errors"
	"net/http"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/targets"
)

func (s *Server) targetRoutes(mux *router) {
	mux.HandleFunc("POST /v1/admin/targets", s.createTarget)
	mux.HandleFunc("PUT /v1/admin/targets/{name}", s.updateTarget)
	mux.HandleFunc("POST /v1/admin/targets/{name}/{op}", s.targetState)
	mux.HandleFunc("POST /v1/admin/targets/{name}/access-levels/{level}/{op}", s.targetState)
	mux.HandleFunc("GET /v1/admin/targets", s.listTargets)
	mux.HandleFunc("GET /v1/admin/targets/{name}", s.getTarget)
	mux.HandleFunc("POST /v1/admin/targets/{name}/bindings/revoke", s.revokeOn)
}

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Targets.Create(r.Context(), caller(r), b)
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Targets.Get(r.Context(), caller(r), cr.ResourceName) })
}

func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Targets.Update(r.Context(), caller(r), name, b)
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Targets.Get(r.Context(), caller(r), name) })
}

// targetState deprecates, reactivates or retires a target, or one of its
// access levels when the path names one.
func (s *Server) targetState(w http.ResponseWriter, r *http.Request) {
	name, level, op := r.PathValue("name"), r.PathValue("level"), r.PathValue("op")
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
	if err == nil && level == "" {
		cr, err = s.Targets.SetState(r.Context(), caller(r), name, op, *b.ExpectedRevision, b.ApprovalReference, b.AutomationContext)
	} else if err == nil {
		cr, err = s.Targets.SetLevelState(r.Context(), caller(r), name, level, op, *b.ExpectedRevision, b.ApprovalReference, b.AutomationContext)
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Targets.Get(r.Context(), caller(r), name) })
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
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
	list, more, err := s.Targets.List(r.Context(), c, targets.Filter{Q: q.Get("q"), Platform: q.Get("platform"),
		PlatformType: q.Get("platformType"), Scope: q.Get("scope"), Label: q.Get("label"), State: q.Get("state"),
		After: cursor.AfterName, Limit: size})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if more {
		cursor.AfterName = list[len(list)-1].Metadata.Name
	}
	if list == nil {
		list = []*targets.View{}
	}
	reply(w, http.StatusOK, map[string]any{"items": list, "nextPageToken": token(more, cursor)})
}

// getTarget: the representation plus the last 20 audit entries.
func (s *Server) getTarget(w http.ResponseWriter, r *http.Request) {
	v, err := s.Targets.Get(r.Context(), caller(r), r.PathValue("name"))
	var entries []auditDTO
	if err == nil {
		entries, _, err = s.auditPage(r.Context(), "TARGET", v.Metadata.Name, nil, 20)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, struct {
		*targets.View
		Audit []auditDTO `json:"audit"`
	}{v, entries})
}

// revokeOn files the bulk revocation of a source's, or a source scope's,
// bindings on a target (containment): 202 with the requests filed, and the
// bindings that could not be revoked with their problem.
func (s *Server) revokeOn(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Source            string `json:"source"`
		SourceScope       string `json:"sourceScope"`
		Comment           string `json:"comment"`
		ApprovalReference string `json:"approvalReference"`
	}
	err := decode(r, &b)
	var out []bindings.Revocation
	if err == nil {
		out, err = s.Bindings.RevokeOn(r.Context(), caller(r), r.PathValue("name"), b.Source, b.SourceScope, b.Comment, b.ApprovalReference)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	requests, failures := []requestDTO{}, []map[string]any{}
	for _, o := range out {
		if o.Error == nil {
			requests = append(requests, dto(o.Request, false))
			continue
		}
		f := map[string]any{"binding": o.Binding, "type": "urn:ligo:problem:internal", "detail": "internal error"}
		if e := (*changerequests.Error)(nil); errors.As(o.Error, &e) {
			f["type"], f["detail"] = "urn:ligo:problem:"+e.Slug, e.Detail
		} else {
			s.Logger.Error("bulk revocation", "request_id", w.Header().Get("X-Request-Id"), "binding", o.Binding, "error", o.Error)
		}
		failures = append(failures, f)
	}
	reply(w, http.StatusAccepted, map[string]any{"changeRequests": requests, "errors": failures})
}
