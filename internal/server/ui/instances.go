package ui

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/instances"
	"go.yaml.in/yaml/v3"
)

// instanceKinds are the UI's paths of the three kinds (.specs/ligo-instances.md §10.3).
var instanceKinds = map[string]instances.Kind{"platforms": instances.Platform, "identity-providers": instances.IdentityProvider,
	"secret-stores": instances.SecretStore}

var kindTitles = map[instances.Kind][2]string{instances.Platform: {"Platforms", "platform"},
	instances.IdentityProvider: {"Identity providers", "identity provider instance"}, instances.SecretStore: {"Secret stores", "secret store instance"}}

// pathOf is the UI path segment of the kind a request names.
func pathOf(r *http.Request) string { return strings.Split(r.Pattern, "/")[2] } // METHOD /ui/<kind>...

// InstanceRow is a row of the identity provider or secret store list.
type InstanceRow struct {
	Name, Type, Realm, Jurisdiction, DisplayName string
}

// InstancesPage is the list of identity provider or secret store instances.
type InstancesPage struct {
	Path, Title, Noun string
	Rows              []InstanceRow
}

// instanceList is GET /ui/identity-providers and /ui/secret-stores: the
// instances in force.
func (s *Server) instanceList(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	path := pathOf(r)
	k := instanceKinds[path]
	d := InstancesPage{Path: path, Title: kindTitles[k][0], Noun: kindTitles[k][1]}
	for _, in := range s.Instances.Current().List(k) {
		d.Rows = append(d.Rows, InstanceRow{Name: in.Metadata.Name, Type: in.Type, Realm: in.Metadata.Realm,
			Jurisdiction: in.Metadata.Jurisdiction, DisplayName: in.Metadata.DisplayName})
	}
	p := s.frame(r, d.Title, "/ui/platforms")
	p.Content = d
	s.page(w, r, http.StatusOK, "instances", p)
}

// InstanceForm is the form of an instance, new or edit: the metadata as
// fields, the rest of the definition as YAML.
type InstanceForm struct {
	Path, Noun                         string
	Edit                               bool
	Revision                           int64
	Name, Type, Realm, Jurisdiction    string
	DisplayName, Description, Contacts string
	Rest                               string
	Types, Realms                      []string
}

// typesOf are the configuration's plugin types of a kind.
func typesOf(cfg *config.Config, k instances.Kind) []string {
	group := map[instances.Kind][]config.PluginType{instances.Platform: cfg.PlatformProviders,
		instances.IdentityProvider: cfg.IdentityProviders, instances.SecretStore: cfg.SecretStores}[k]
	var out []string
	for _, t := range group {
		out = append(out, t.Type)
	}
	return out
}

func (s *Server) instanceForm(r *http.Request, path string) InstanceForm {
	k := instanceKinds[path]
	f := InstanceForm{Path: path, Noun: kindTitles[k][1], Types: typesOf(s.Config, k)}
	for _, z := range s.Config.Realms {
		f.Realms = append(f.Realms, z.Name)
	}
	return f
}

func (s *Server) instanceNewForm(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	f := s.instanceForm(r, pathOf(r))
	f.Rest = "svidSelector:\n  matchExpr: ''\nconfig: {}\n"
	p := s.frame(r, "New "+f.Noun, "/ui/platforms")
	p.Content = f
	s.page(w, r, http.StatusOK, "instance-form", p)
}

// instanceEditForm shows the definition to those who file and decide its
// requests; to others it is not found, as in the API (§10.1).
func (s *Server) instanceEditForm(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	path := pathOf(r)
	revision, d, decider, err := s.InstanceService.Get(r.Context(), session(r).Caller(), instanceKinds[path], r.PathValue("name"))
	if err == nil && !decider {
		err = &changerequests.Error{Status: http.StatusNotFound, Slug: "not-found", Detail: "only the operators and approvers of " + d.Metadata.Jurisdiction + " see its definition"}
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := s.instanceForm(r, path)
	f.Edit, f.Revision, f.Name, f.Type, f.Realm, f.Jurisdiction = true, revision, d.Metadata.Name, d.Type, d.Metadata.Realm, d.Metadata.Jurisdiction
	f.DisplayName, f.Description = d.Metadata.DisplayName, d.Metadata.Description
	for _, c := range d.Metadata.Contacts {
		f.Contacts += c.Name + " <" + c.Email + ">\n"
	}
	f.Rest, err = rest(d)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := s.frame(r, "Edit "+d.Metadata.Name, "/ui/platforms")
	p.Content = f
	s.page(w, r, http.StatusOK, "instance-form", p)
}

// rest is a definition without its kind, metadata and type, as YAML.
func rest(d *instances.Definition) (string, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return "", err
	}
	delete(m, "kind")
	delete(m, "metadata")
	delete(m, "type")
	out, err := yaml.Marshal(m)
	return string(out), err
}

// instanceOf reads the form into a definition body.
func instanceOf(r *http.Request, k instances.Kind) (map[string]any, error) {
	body := map[string]any{}
	if err := yaml.Unmarshal([]byte(r.PostFormValue("rest")), &body); err != nil {
		return nil, &changerequests.Error{Status: http.StatusUnprocessableEntity, Slug: "validation-failed", Detail: "the definition is not YAML or JSON: " + err.Error()}
	}
	if body == nil {
		body = map[string]any{}
	}
	for _, key := range []string{"kind", "metadata", "type"} {
		if _, ok := body[key]; ok {
			return nil, &changerequests.Error{Status: http.StatusUnprocessableEntity, Slug: "validation-failed", Detail: key + " is set by the fields above, not in the definition"}
		}
	}
	meta := map[string]any{"name": strings.TrimSpace(r.PostFormValue("name")), "realm": r.PostFormValue("realm"),
		"jurisdiction": strings.TrimSpace(r.PostFormValue("jurisdiction"))}
	if v := strings.TrimSpace(r.PostFormValue("displayName")); v != "" {
		meta["displayName"] = v
	}
	if v := strings.TrimSpace(r.PostFormValue("description")); v != "" {
		meta["description"] = v
	}
	if cs := contacts(r.PostFormValue("contacts")); len(cs) > 0 {
		meta["contacts"] = cs
	}
	body["kind"], body["metadata"], body["type"] = k.ManifestKind(), meta, r.PostFormValue("type")
	return body, nil
}

// instanceSubmit is POST /ui/{kind} and PUT /ui/{kind}/{name}: the plugin's
// schema and every other check of §6 answer in the form.
func (s *Server) instanceSubmit(w http.ResponseWriter, r *http.Request) {
	path := pathOf(r)
	k := instanceKinds[path]
	body, err := instanceOf(r, k)
	if err != nil {
		s.filed(w, r, nil, err, "")
		return
	}
	ctx, c := r.Context(), session(r).Caller()
	var cr *changerequests.Request
	if name := r.PathValue("name"); name != "" {
		rev, perr := strconv.ParseInt(r.PostFormValue("expectedRevision"), 10, 64)
		if perr != nil {
			s.alert(w, r, http.StatusUnprocessableEntity, "The form lost its revision: reload it.")
			return
		}
		body["expectedRevision"] = rev
		b, _ := json.Marshal(body)
		cr, err = s.InstanceService.Update(ctx, c, k, name, b)
	} else {
		b, _ := json.Marshal(body)
		cr, err = s.InstanceService.Create(ctx, c, k, b)
	}
	s.filed(w, r, cr, err, "/ui/"+path)
}

// instanceRetire is DELETE /ui/{kind}/{name}: the retirement, refused while
// the instance is in use (§6 rule 9).
func (s *Server) instanceRetire(w http.ResponseWriter, r *http.Request) {
	path := pathOf(r)
	rev, err := strconv.ParseInt(r.FormValue("expectedRevision"), 10, 64)
	if err != nil {
		s.alert(w, r, http.StatusUnprocessableEntity, "The page lost its revision: reload it.")
		return
	}
	cr, err := s.InstanceService.Retire(r.Context(), session(r).Caller(), instanceKinds[path], r.PathValue("name"),
		changerequests.Common{ExpectedRevision: &rev})
	s.filed(w, r, cr, err, "/ui/"+path)
}
