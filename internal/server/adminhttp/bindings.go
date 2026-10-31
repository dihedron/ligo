package adminhttp

import (
	"context"
	"net/http"
	"strconv"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
)

// Workflows starts the workflows of operational actions: *workflows.Engine.
type Workflows interface {
	Retry(ctx context.Context, bindingID uuid.UUID, actor string) (dbos.WorkflowHandle[string], error)
	Rotate(ctx context.Context, bindingID uuid.UUID, actor string) (dbos.WorkflowHandle[string], error)
}

func (s *Server) bindingRoutes(mux *router) {
	mux.HandleFunc("POST /v1/admin/bindings", s.createBinding)
	mux.HandleFunc("PUT /v1/admin/bindings/{name}", s.updateBinding)
	mux.HandleFunc("DELETE /v1/admin/bindings/{name}", s.deleteBinding)
	mux.HandleFunc("GET /v1/admin/bindings", s.listBindings)
	mux.HandleFunc("GET /v1/admin/bindings/{name}", s.getBinding)
	mux.HandleFunc("GET /v1/admin/bindings/{name}/flows", s.bindingFlows)
	mux.HandleFunc("POST /v1/admin/bindings/{name}/retry", s.operate)
	mux.HandleFunc("POST /v1/admin/bindings/{name}/rotate", s.operate)
	mux.HandleFunc("GET /v1/admin/sources/{name}/bindings", s.bindingsOf)
	mux.HandleFunc("GET /v1/admin/targets/{name}/bindings", s.bindingsOf)
	mux.HandleFunc("POST /v1/admin/break-glass", s.breakGlass)
	mux.HandleFunc("GET /v1/admin/break-glass", func(w http.ResponseWriter, r *http.Request) {
		s.listKind(w, r, changerequests.KindBreakGlass)
	})
}

func (s *Server) createBinding(w http.ResponseWriter, r *http.Request) {
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Bindings.Create(r.Context(), caller(r), b)
	}
	if err == nil && cr.Status == "APPLIED" && r.URL.Query().Get("wait") == "true" {
		v, err := s.settled(r.Context(), caller(r), cr.ResourceName)
		if err == nil {
			reply(w, http.StatusOK, map[string]any{"changeRequest": dto(cr, false), "resource": v})
			return
		}
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Bindings.Get(r.Context(), caller(r), cr.ResourceName) })
}

// settled waits up to 10s for the binding to reach a terminal phase
// (?wait=true, §7.2.3); a binding still in flight is no error.
func (s *Server) settled(ctx context.Context, c changerequests.Caller, name string) (*bindings.View, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		v, err := s.Bindings.Get(ctx, c, name)
		if err != nil || v.Status.Phase != "PROVISIONING" && v.Status.Phase != "DELETING" {
			return v, err
		}
		select {
		case <-ctx.Done():
			return v, nil
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *Server) updateBinding(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Bindings.Update(r.Context(), caller(r), name, b)
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Bindings.Get(r.Context(), caller(r), name) })
}

// deleteBinding files a revocation; expectedRevision is a query parameter,
// approvalReference and automationContext come in an optional body.
func (s *Server) deleteBinding(w http.ResponseWriter, r *http.Request) {
	revision, err := strconv.ParseInt(r.URL.Query().Get("expectedRevision"), 10, 64)
	if err != nil {
		s.fail(w, r, &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "expectedRevision is required"})
		return
	}
	var b stateChange
	if r.ContentLength != 0 {
		err = decode(r, &b)
	}
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Bindings.Delete(r.Context(), caller(r), r.PathValue("name"), revision, b.ApprovalReference, b.AutomationContext)
	}
	s.filed(w, r, cr, err, nil)
}

func (s *Server) listBindings(w http.ResponseWriter, r *http.Request) {
	s.bindingList(w, r, bindings.Filter{})
}

// bindingsOf lists the bindings of a source or a target the caller sees.
func (s *Server) bindingsOf(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var f bindings.Filter
	var err error
	if r.Pattern == "GET /v1/admin/sources/{name}/bindings" {
		f.Source = name
		_, err = s.Sources.Get(r.Context(), caller(r), name)
	} else {
		f.Target = name
		_, err = s.Targets.Get(r.Context(), caller(r), name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.bindingList(w, r, f)
}

func (s *Server) bindingList(w http.ResponseWriter, r *http.Request, f bindings.Filter) {
	c := caller(r)
	if !viewer(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	var cursor struct {
		AfterName string `json:"afterName"`
	}
	size, err := page(r, &cursor)
	q := r.URL.Query()
	if v := q.Get("expiringBefore"); err == nil && v != "" {
		var t time.Time
		if t, err = time.Parse(time.RFC3339, v); err != nil {
			err = &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "expiringBefore: RFC 3339"}
		}
		f.ExpiringBefore = &t
	}
	if v := q.Get("propagationPending"); err == nil && v != "" {
		p := v == "true"
		f.PropagationPending = &p
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for key, field := range map[string]*string{"source": &f.Source, "target": &f.Target, "accessLevel": &f.AccessLevel,
		"platform": &f.Platform, "platformType": &f.PlatformType, "phase": &f.Phase, "trustDomain": &f.TrustDomain, "zone": &f.Zone,
		"scope": &f.Scope} {
		if v := q.Get(key); v != "" && *field == "" {
			*field = v
		}
	}
	f.After, f.Limit = cursor.AfterName, size
	list, more, err := s.Bindings.List(r.Context(), c, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if more {
		cursor.AfterName = list[len(list)-1].Metadata.Name
	}
	if list == nil {
		list = []*bindings.View{}
	}
	reply(w, http.StatusOK, map[string]any{"items": list, "nextPageToken": token(more, cursor)})
}

// getBinding: the representation, its stages without secrets and the last
// 20 audit entries.
func (s *Server) getBinding(w http.ResponseWriter, r *http.Request) {
	v, err := s.Bindings.Get(r.Context(), caller(r), r.PathValue("name"))
	var stages []bindings.Stage
	var entries []auditDTO
	if err == nil {
		stages, err = s.Bindings.Stages(r.Context(), v)
	}
	if err == nil {
		entries, _, err = s.auditPage(r.Context(), "BINDING", v.Metadata.Name, nil, 20)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, struct {
		*bindings.View
		Stages []bindings.Stage `json:"stages"`
		Audit  []auditDTO       `json:"audit"`
	}{v, stages, entries})
}

func (s *Server) bindingFlows(w http.ResponseWriter, r *http.Request) {
	v, err := s.Bindings.Get(r.Context(), caller(r), r.PathValue("name"))
	if err == nil {
		var out any
		if out, err = s.Bindings.Flows(r.Context(), v); err == nil {
			reply(w, http.StatusOK, map[string]any{"binding": v.Metadata.Name, "networkFlows": out})
			return
		}
	}
	s.fail(w, r, err)
}

// operate retries or rotates a binding, for an operator of one of its
// scopes; maintenance mode refuses both (§10.3).
func (s *Server) operate(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	v, err := s.Bindings.Get(r.Context(), c, r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m := v.Metadata
	if !c.Grants.Operator(m.SourceScope) && !c.Grants.Operator(m.TargetScope) && !c.Grants.Operator(m.PlatformScope) {
		problem(w, http.StatusForbidden, "forbidden", "operator role on one of the binding's scopes required")
		return
	}
	act := s.Workflows.Retry
	if r.Pattern == "POST /v1/admin/bindings/{name}/rotate" {
		act = s.Workflows.Rotate
	}
	if _, err := act(r.Context(), m.ID, c.ID()); err != nil {
		s.fail(w, r, err)
		return
	}
	if v, err = s.Bindings.Get(r.Context(), c, m.Name); err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusAccepted, map[string]any{"binding": v})
}

// breakGlass needs LDAP Basic credentials on the request itself: the
// middleware has just verified them and read the groups afresh; SVID
// callers are refused (§7.2.3 "Break-glass operations").
func (s *Server) breakGlass(w http.ResponseWriter, r *http.Request) {
	if _, _, basic := r.BasicAuth(); !basic || caller(r).Principal.SPIFFEID != "" {
		problem(w, http.StatusForbidden, "forbidden", "break-glass needs LDAP Basic credentials on the request")
		return
	}
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.Bindings.BreakGlass(r.Context(), caller(r), b)
	}
	s.filed(w, r, cr, err, func() (any, error) { return s.Bindings.Get(r.Context(), caller(r), cr.ResourceName) })
}
