package adminhttp

import (
	"encoding/json"
	"net/http"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
)

func (s *Server) requestRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/change-requests", s.listRequests)
	mux.HandleFunc("GET /v1/admin/change-requests/{id}", s.getRequest)
	mux.HandleFunc("POST /v1/admin/change-requests/{id}/approve", s.approve)
	mux.HandleFunc("POST /v1/admin/change-requests/{id}/decline", s.decline)
	mux.HandleFunc("POST /v1/admin/change-requests/{id}/withdraw", s.withdraw)
	mux.HandleFunc("POST /v1/admin/change-requests/{id}/ratify", s.ratify)
	mux.HandleFunc("POST /v1/admin/change-requests/{id}/revert", s.revert)
}

// sideDTO and requestDTO are the change request representation (§7.2.3).
type sideDTO struct {
	Side                string     `json:"side"`
	Scope               string     `json:"scope"`
	Basis               string     `json:"basis"`
	Decision            *string    `json:"decision"`
	DecidedBy           string     `json:"decidedBy,omitempty"`
	DecidedAt           *time.Time `json:"decidedAt,omitempty"`
	RatifiedBy          string     `json:"ratifiedBy,omitempty"`
	RatifiedAt          *time.Time `json:"ratifiedAt,omitempty"`
	RatificationComment string     `json:"ratificationComment,omitempty"`
}

type requestDTO struct {
	ID                        uuid.UUID       `json:"id"`
	ResourceType              string          `json:"resourceType"`
	ResourceName              string          `json:"resourceName"`
	ResourceID                *uuid.UUID      `json:"resourceId"`
	Operation                 string          `json:"operation"`
	Kind                      string          `json:"kind"`
	Consent                   string          `json:"consent"`
	Status                    string          `json:"status"`
	Zone                      string          `json:"zone,omitempty"`
	OwnerScope                string          `json:"ownerScope,omitempty"`
	SourceScope               string          `json:"sourceScope,omitempty"`
	TargetScope               string          `json:"targetScope,omitempty"`
	PlatformScope             string          `json:"platformScope,omitempty"`
	InterconnectRule          string          `json:"interconnectRule,omitempty"`
	DependsOn                 *uuid.UUID      `json:"dependsOn"`
	RevertsChangeRequest      *uuid.UUID      `json:"revertsChangeRequest,omitempty"`
	PolicySHA256              string          `json:"policySha256"`
	DistinctApproversRequired bool            `json:"distinctApproversRequired"`
	PayloadSHA256             string          `json:"payloadSha256"`
	Payload                   json.RawMessage `json:"payload,omitempty"`
	ApprovalReference         string          `json:"approvalReference,omitempty"`
	RequestedBy               string          `json:"requestedBy"`
	RequestedAt               time.Time       `json:"requestedAt"`
	ExpiresAt                 time.Time       `json:"expiresAt"`
	Sides                     []sideDTO       `json:"sides"`
	AwaitingApproval          []string        `json:"awaitingApproval"`
}

func dto(r *changerequests.Request, full bool) requestDTO {
	d := requestDTO{ID: r.ID, ResourceType: r.ResourceType, ResourceName: r.ResourceName, ResourceID: r.ResourceID, Operation: r.Operation,
		Kind: r.Kind, Consent: r.Consent, Status: r.Status, Zone: r.Zone, OwnerScope: r.OwnerScope, SourceScope: r.SourceScope,
		TargetScope: r.TargetScope, PlatformScope: r.PlatformScope, InterconnectRule: r.InterconnectRule, DependsOn: r.DependsOn,
		RevertsChangeRequest: r.RevertsID, PolicySHA256: r.PolicySHA256, DistinctApproversRequired: r.DistinctApprovers,
		PayloadSHA256: r.PayloadSHA256, ApprovalReference: r.ApprovalReference, RequestedBy: r.RequestedBy, RequestedAt: r.RequestedAt,
		ExpiresAt: r.ExpiresAt, Sides: []sideDTO{}, AwaitingApproval: []string{}}
	if d.Kind == "" {
		d.Kind = "STANDARD"
	}
	if full {
		d.Payload = r.Payload
	}
	for _, sd := range r.Sides {
		x := sideDTO{Side: sd.Name, Scope: sd.Scope, Basis: sd.Basis, DecidedBy: sd.DecidedBy, DecidedAt: sd.DecidedAt,
			RatifiedBy: sd.RatifiedBy, RatifiedAt: sd.RatifiedAt, RatificationComment: sd.RatificationNote}
		if sd.Decision != "" {
			x.Decision = &sd.Decision
		} else if r.Status == "PENDING" {
			d.AwaitingApproval = append(d.AwaitingApproval, sd.Name)
		}
		d.Sides = append(d.Sides, x)
	}
	return d
}

func (s *Server) listRequests(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !viewer(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	var cursor struct {
		BeforeID *uuid.UUID `json:"beforeId"`
	}
	size, err := page(r, &cursor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	list, more, err := s.Requests.List(r.Context(), c, changerequests.Filter{Status: q.Get("status"), ResourceType: q.Get("resourceType"),
		ResourceName: q.Get("resourceName"), Zone: q.Get("zone"), Scope: q.Get("scope"), AwaitingMe: q.Get("awaitingMe") == "true",
		Before: cursor.BeforeID, Limit: size})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]requestDTO, 0, len(list))
	for _, cr := range list {
		items = append(items, dto(cr, false))
	}
	if more {
		cursor.BeforeID = &list[len(list)-1].ID
	}
	reply(w, http.StatusOK, map[string]any{"items": items, "nextPageToken": token(more, cursor)})
}

func (s *Server) getRequest(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err == nil {
		var cr *changerequests.Request
		if cr, err = s.Requests.Get(r.Context(), caller(r), id); err == nil {
			reply(w, http.StatusOK, dto(cr, true))
			return
		}
	}
	s.fail(w, r, err)
}

// decision is the body of approve, decline, ratify and withdraw.
type decision struct {
	PayloadSHA256 string `json:"payloadSha256"`
	Comment       string `json:"comment"`
	Side          string `json:"side"`
}

// decide decodes the body and runs act with the request's id.
func (s *Server) decide(w http.ResponseWriter, r *http.Request, commentRequired bool, act func(uuid.UUID, decision) (*changerequests.Request, error)) {
	id, err := pathID(r)
	var d decision
	if err == nil && r.ContentLength != 0 {
		err = decode(r, &d)
	}
	if err == nil && commentRequired && d.Comment == "" {
		err = &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "comment is required"}
	}
	var cr *changerequests.Request
	if err == nil {
		cr, err = act(id, d)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"changeRequest": dto(cr, false)})
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, false, func(id uuid.UUID, d decision) (*changerequests.Request, error) {
		return s.Requests.Approve(r.Context(), caller(r), id, d.PayloadSHA256, d.Side, d.Comment)
	})
}

func (s *Server) decline(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, true, func(id uuid.UUID, d decision) (*changerequests.Request, error) {
		return s.Requests.Decline(r.Context(), caller(r), id, d.Side, d.Comment)
	})
}

func (s *Server) withdraw(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, false, func(id uuid.UUID, d decision) (*changerequests.Request, error) {
		if err := s.Requests.Withdraw(r.Context(), caller(r), id, d.Comment); err != nil {
			return nil, err
		}
		return s.Requests.Get(r.Context(), caller(r), id)
	})
}

func (s *Server) ratify(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, true, func(id uuid.UUID, d decision) (*changerequests.Request, error) {
		return s.Bindings.Ratify(r.Context(), caller(r), id, d.Side, d.Comment)
	})
}

func (s *Server) revert(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, false, func(id uuid.UUID, _ decision) (*changerequests.Request, error) {
		return s.Bindings.RevertNow(r.Context(), caller(r), id)
	})
}
