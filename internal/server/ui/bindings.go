package ui

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/flows"
)

const pageSize = 50

// fail renders an error page, or an alert for an htmx request, for a
// service error: its status and detail, else 500 (logged).
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, detail := http.StatusInternalServerError, "The page cannot be shown now. Try again later."
	var e *changerequests.Error
	if errors.As(err, &e) {
		status, detail = e.Status, e.Detail
	} else {
		s.Logger.Error("ui", "path", r.URL.Path, "request_id", w.Header().Get("X-Request-Id"), "error", err)
	}
	if r.Header.Get("HX-Request") != "" {
		s.alert(w, r, status, detail)
		return
	}
	p := s.frame(r, http.StatusText(status), "")
	p.Content = Alert{Message: detail, RequestID: w.Header().Get("X-Request-Id")}
	s.page(w, r, status, "error", p)
}

// forbidden refuses a page to a session without a viewer role.
func (s *Server) readable(w http.ResponseWriter, r *http.Request) bool {
	if !session(r).Grants.Viewer() {
		s.fail(w, r, &changerequests.Error{Status: http.StatusForbidden, Slug: "forbidden", Detail: "A viewer role is required to see this page."})
		return false
	}
	return true
}

// Dashboard is the bindings page's data (§7.4 routes, GET /ui/bindings).
type Dashboard struct {
	Filter     bindings.Filter
	Phases     []string
	Bindings   []*bindings.View
	Next       string // the after= of the next page, "" on the last
	AwaitingMe []*changerequests.Request
	BreakGlass []OpenBreakGlass
}

var phases = []string{"PENDING", "PROVISIONING", "ACTIVE", "FAILED", "DELETING", "DELETE_FAILED"}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	c, q := session(r).Caller(), r.URL.Query()
	f := bindings.Filter{Source: q.Get("source"), Target: q.Get("target"), AccessLevel: q.Get("accessLevel"), Phase: q.Get("phase"),
		Platform: q.Get("platform"), After: q.Get("after"), Limit: pageSize}
	if q.Get("expiring") == "7d" {
		t := time.Now().Add(7 * 24 * time.Hour)
		f.ExpiringBefore = &t
	}
	list, more, err := s.Bindings.List(r.Context(), c, f)
	var awaiting []*changerequests.Request
	if err == nil {
		awaiting, _, err = s.Requests.List(r.Context(), c, changerequests.Filter{Status: "PENDING", AwaitingMe: true, Limit: 20})
	}
	var open []OpenBreakGlass
	if err == nil {
		open, err = s.openBreakGlass(r.Context())
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := Dashboard{Filter: f, Phases: phases, Bindings: list, AwaitingMe: awaiting, BreakGlass: open}
	if more {
		d.Next = list[len(list)-1].Metadata.Name
	}
	p := s.frame(r, "Bindings", "/ui/bindings")
	p.BreakGlass, p.Content = open, d
	s.page(w, r, http.StatusOK, "bindings", p)
}

// openBreakGlass lists the applied, unratified break-glass changes still
// within their TTL (ADR-12), for the dashboard's banner.
func (s *Server) openBreakGlass(ctx context.Context) ([]OpenBreakGlass, error) {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT r.resource_name, r.requested_at + make_interval(secs => r.break_glass_ttl_seconds)
		FROM change_requests r JOIN change_request_sides s ON s.change_request_id = r.id
		WHERE r.kind = 'BREAK_GLASS' AND r.status = 'APPLIED' AND s.basis = 'BREAK_GLASS' AND s.ratified_by IS NULL
		AND r.requested_at + make_interval(secs => r.break_glass_ttl_seconds) > now() ORDER BY 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpenBreakGlass
	for rows.Next() {
		var name string
		var expires time.Time
		if err := rows.Scan(&name, &expires); err != nil {
			return nil, err
		}
		out = append(out, OpenBreakGlass{Name: name, ExpiresIn: time.Until(expires).Round(time.Minute).String()})
	}
	return out, rows.Err()
}

// Entry is an audit entry of a resource's trail.
type Entry struct {
	Action, Actor string
	Revision      *int64
	OccurredAt    time.Time
}

// trail is a resource's last 20 audit entries.
func (s *Server) trail(ctx context.Context, typ, name string) ([]Entry, error) {
	rows, err := s.DB.Query(ctx, `SELECT action, actor, revision, occurred_at FROM audit_log
		WHERE resource_type = $1 AND resource_name = $2 ORDER BY id DESC LIMIT 20`, typ, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Action, &e.Actor, &e.Revision, &e.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Step is one stage of the provisioning stepper.
type Step struct {
	Number int
	Name   string
	State  string // done, active or ""
}

// StatusRow is the polled status of a binding (§7.4, status-row).
type StatusRow struct {
	Name    string
	Phase   string
	Message string
	Steps   []Step
	Polling bool // while PROVISIONING or DELETING
}

var stageLabels = map[string]string{"IDENTITY": "Identity", "TARGET": "Target", "SECRET_STORE": "Secret Store"}

// statusRow is the stepper [1. Identity] → [2. Target] → [3. Secret Store],
// reversed for a delete: an apply's stages come from their rows (ENSURED
// done, STARTED active), a delete's from the current step (CLEANUP_x,
// CLEANED_x).
func statusRow(v *bindings.View, stages []bindings.Stage) StatusRow {
	row := StatusRow{Name: v.Metadata.Name, Phase: v.Status.Phase, Message: v.Status.Message,
		Polling: v.Status.Phase == "PROVISIONING" || v.Status.Phase == "DELETING"}
	order := []string{"IDENTITY", "TARGET", "SECRET_STORE"}
	deleting := v.Status.Phase == "DELETING" || v.Status.Phase == "DELETE_FAILED"
	if deleting {
		slices.Reverse(order)
	}
	status := map[string]string{}
	for _, st := range stages {
		status[st.Stage] = st.Status
	}
	reached := -1
	for i, name := range order {
		if deleting && (v.Status.CurrentStep == "CLEANUP_"+name || v.Status.CurrentStep == "CLEANED_"+name) {
			reached = i
		}
	}
	for i, name := range order {
		st := Step{Number: i + 1, Name: stageLabels[name]}
		switch {
		case !deleting && status[name] == "ENSURED":
			st.State = "done"
		case !deleting && status[name] == "STARTED":
			st.State = "active"
		case deleting && (i < reached || i == reached && strings.HasPrefix(v.Status.CurrentStep, "CLEANED_")):
			st.State = "done"
		case deleting && i == reached:
			st.State = "active"
		}
		row.Steps = append(row.Steps, st)
	}
	return row
}

// BindingPage is the binding detail's data.
type BindingPage struct {
	Binding *bindings.View
	Row     StatusRow
	Stages  []bindings.Stage
	Flows   []flows.Flow
	Audit   []Entry
}

func (s *Server) binding(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	ctx := r.Context()
	v, err := s.Bindings.Get(ctx, session(r).Caller(), r.PathValue("name"))
	var d BindingPage
	if err == nil {
		d.Binding = v
		d.Stages, err = s.Bindings.Stages(ctx, v)
	}
	if err == nil {
		d.Flows, err = s.Bindings.Flows(ctx, v)
	}
	if err == nil {
		d.Audit, err = s.trail(ctx, "BINDING", v.Metadata.Name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Row = statusRow(v, d.Stages)
	p := s.frame(r, v.Metadata.Name, "/ui/bindings")
	p.Content = d
	s.page(w, r, http.StatusOK, "binding", p)
}

// bindingStatus is GET /ui/bindings/{name}/status-row: polled every 2s
// while in flight; the terminal row has no hx-trigger, which stops the
// polling (§7.4).
func (s *Server) bindingStatus(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	v, err := s.Bindings.Get(r.Context(), session(r).Caller(), r.PathValue("name"))
	var stages []bindings.Stage
	if err == nil {
		stages, err = s.Bindings.Stages(r.Context(), v)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.fragment(w, r, http.StatusOK, "status-row", statusRow(v, stages))
}

// Requests is the change-request queue's data.
type Requests struct {
	Awaiting bool
	Status   string
	Requests []*changerequests.Request
	Next     string // the before= of the next page
}

func (s *Server) changeRequests(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	q := r.URL.Query()
	f := changerequests.Filter{Status: q.Get("status"), AwaitingMe: q.Get("awaiting") == "me", ResourceType: strings.ToUpper(q.Get("type")),
		Limit: pageSize}
	if b := q.Get("before"); b != "" {
		id, err := uuid.Parse(b)
		if err != nil {
			s.fail(w, r, &changerequests.Error{Status: http.StatusUnprocessableEntity, Slug: "validation-failed", Detail: "before: not an id"})
			return
		}
		f.Before = &id
	}
	if f.AwaitingMe {
		f.Status = "PENDING"
	}
	list, more, err := s.Requests.List(r.Context(), session(r).Caller(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := Requests{Awaiting: f.AwaitingMe, Status: f.Status, Requests: list}
	if more {
		d.Next = list[len(list)-1].ID.String()
	}
	p := s.frame(r, "Change requests", "/ui/change-requests")
	p.Content = d
	s.page(w, r, http.StatusOK, "change-requests", p)
}

// RequestPage is a change request's data: its sides with the user's
// controls and, for an update, its diff against the resource.
type RequestPage struct {
	Request  *changerequests.Request
	Decision Decision
	Diff     any
}

func (s *Server) changeRequest(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, &changerequests.Error{Status: http.StatusNotFound, Slug: "not-found", Detail: "No such change request."})
		return
	}
	cr, err := s.Requests.Get(r.Context(), session(r).Caller(), id)
	var d RequestPage
	if err == nil {
		d.Request, d.Decision = cr, s.decision(r, cr)
		d.Diff, err = s.Requests.DiffOf(r.Context(), cr)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := s.frame(r, "Change request", "/ui/change-requests")
	p.Content = d
	s.page(w, r, http.StatusOK, "change-request", p)
}
