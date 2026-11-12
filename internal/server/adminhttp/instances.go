package adminhttp

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/instances"
	"github.com/dihedron/ligo/internal/sources"
)

// instancePaths are the API's names of the three kinds (.specs/ligo-instances.md §10.1).
var instancePaths = map[string]instances.Kind{"platforms": instances.Platform, "identity-providers": instances.IdentityProvider,
	"secret-stores": instances.SecretStore}

func (s *Server) instanceRoutes(mux *router) {
	for path := range instancePaths {
		mux.HandleFunc("POST /v1/admin/"+path, s.createInstance)
		mux.HandleFunc("PUT /v1/admin/"+path+"/{name}", s.updateInstance)
		mux.HandleFunc("DELETE /v1/admin/"+path+"/{name}", s.retireInstance)
		if path != "platforms" { // platforms keep their own reads, with health and forms
			mux.HandleFunc("GET /v1/admin/"+path, s.listInstances)
			mux.HandleFunc("GET /v1/admin/"+path+"/{name}", s.getInstance)
		}
	}
}

// kindOf is the kind a request's path names.
func kindOf(r *http.Request) instances.Kind {
	return instancePaths[strings.Split(r.Pattern, "/")[3]] // METHOD /v1/admin/<kind>...
}

func (s *Server) createInstance(w http.ResponseWriter, r *http.Request) {
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.InstanceService.Create(r.Context(), caller(r), kindOf(r), b)
	}
	s.filed(w, r, cr, err, nil)
}

func (s *Server) updateInstance(w http.ResponseWriter, r *http.Request) {
	b, err := body(r)
	var cr *changerequests.Request
	if err == nil {
		cr, err = s.InstanceService.Update(r.Context(), caller(r), kindOf(r), r.PathValue("name"), b)
	}
	s.filed(w, r, cr, err, nil)
}

// retireInstance files a DELETE, which retires the instance (§4.3).
func (s *Server) retireInstance(w http.ResponseWriter, r *http.Request) {
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
		cr, err = s.InstanceService.Retire(r.Context(), caller(r), kindOf(r), r.PathValue("name"),
			changerequests.Common{ExpectedRevision: &revision, ApprovalReference: b.ApprovalReference, AutomationContext: b.AutomationContext})
	}
	s.filed(w, r, cr, err, nil)
}

// instanceDTO is an identity provider or secret store instance as any
// viewer sees it; its revision and definition are for those who file and
// decide its requests (§10.1).
type instanceDTO struct {
	APIVersion   string                `json:"apiVersion"`
	Kind         string                `json:"kind"`
	Name         string                `json:"name"`
	Type         string                `json:"type"`
	Realm        string                `json:"realm"`
	Jurisdiction string                `json:"jurisdiction"`
	DisplayName  string                `json:"displayName,omitempty"`
	Description  string                `json:"description,omitempty"`
	Contacts     []sources.Contact     `json:"contacts,omitempty"`
	NetworkFlows []flows.Flow          `json:"networkFlows"`
	Revision     *int64                `json:"revision,omitempty"`
	Definition   *instances.Definition `json:"definition,omitempty"`
	Quarantined  bool                  `json:"quarantined,omitempty"` // its row does not verify: not in force
}

func instanceOf(d *instances.Definition) instanceDTO {
	out := instanceDTO{APIVersion: sources.APIVersion, Kind: d.Kind, Name: d.Metadata.Name, Type: d.Type, Realm: d.Metadata.Realm,
		Jurisdiction: d.Metadata.Jurisdiction, DisplayName: d.Metadata.DisplayName, Description: d.Metadata.Description, NetworkFlows: d.NetworkFlows}
	for _, c := range d.Metadata.Contacts {
		out.Contacts = append(out.Contacts, sources.Contact{Name: c.Name, Email: c.Email})
	}
	if out.NetworkFlows == nil {
		out.NetworkFlows = []flows.Flow{}
	}
	return out
}

// listInstances: the instances in force of a kind, by name, to any viewer.
func (s *Server) listInstances(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	items := []instanceDTO{}
	for _, d := range s.Instances.Current().List(kindOf(r)) {
		items = append(items, instanceOf(d))
	}
	reply(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getInstance(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	revision, d, decider, err := s.InstanceService.Get(r.Context(), caller(r), kindOf(r), r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := instanceOf(d)
	if _, inForce := s.Instances.Current().Get(kindOf(r), d.Metadata.Name); !inForce {
		out.Quarantined = true
	}
	if decider {
		out.Revision, out.Definition = &revision, d
	}
	reply(w, http.StatusOK, out)
}

// decided adds a platform's revision and definition for those who file and
// decide its requests.
func (s *Server) decided(r *http.Request, d *platformDTO) {
	revision, def, decider, err := s.InstanceService.Get(r.Context(), caller(r), instances.Platform, d.Name)
	if err == nil && decider {
		d.Revision, d.Definition = &revision, def
	}
}
