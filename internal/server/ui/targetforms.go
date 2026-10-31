package ui

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/targets"
)

// Plugins calls a platform's plugin (adminhttp.Plugins).
type Plugins interface {
	Health(ctx context.Context, platform string) (*pluginv1.HealthResponse, error)
	UISchemas(ctx context.Context, platform string) (*pluginv1.GetUISchemasResponse, error)
}

// UISchema rendering rules (INV-12).
var jsonKey = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

const (
	maxFields  = 64
	maxOptions = 500
)

// Option is a select's option.
type Option struct {
	Label, Value string
	Selected     bool
}

// Field is a UISchema field as plain data for the templates (INV-12): its
// form name, a key checked against its grammar, at most 500 options, and a
// pattern only if the regex compiles as RE2.
type Field struct {
	Name, Key, Label, Type, Value, Placeholder, Help, Pattern string
	Required, Checked                                         bool
	Options                                                   []Option
}

var fieldTypes = map[pluginv1.UIFieldType]string{pluginv1.UIFieldType_UI_FIELD_TYPE_TEXT: "text", pluginv1.UIFieldType_UI_FIELD_TYPE_NUMBER: "number",
	pluginv1.UIFieldType_UI_FIELD_TYPE_BOOLEAN: "checkbox", pluginv1.UIFieldType_UI_FIELD_TYPE_SELECT: "select",
	pluginv1.UIFieldType_UI_FIELD_TYPE_MULTISELECT: "multiselect", pluginv1.UIFieldType_UI_FIELD_TYPE_TEXTAREA: "textarea"}

// descriptors are a form's usable descriptors: a valid key and a known type,
// at most 64; the plugin is told nothing, the rest is logged.
func (s *Server) descriptors(f *pluginv1.UIForm) []*pluginv1.UIFieldDescriptor {
	var out []*pluginv1.UIFieldDescriptor
	for _, d := range f.GetFields() {
		if _, ok := fieldTypes[d.GetFieldType()]; !ok || !jsonKey.MatchString(d.GetJsonKey()) {
			s.Logger.Warn("ui: a UISchema field is not rendered", "json_key", d.GetJsonKey(), "type", d.GetFieldType())
			continue
		}
		if len(out) == maxFields {
			break
		}
		out = append(out, d)
	}
	return out
}

// fields renders a form's descriptors under prefix with values (a JSON
// object's fields).
func (s *Server) fields(f *pluginv1.UIForm, prefix string, values map[string]any) []Field {
	var out []Field
	for _, d := range s.descriptors(f) {
		fd := Field{Name: prefix + d.GetJsonKey(), Key: d.GetJsonKey(), Label: d.GetLabel(), Type: fieldTypes[d.GetFieldType()],
			Required: d.GetRequired(), Placeholder: d.GetPlaceholder(), Help: d.GetHelpText(), Value: d.GetDefaultValue()}
		if fd.Label == "" {
			fd.Label = fd.Key
		}
		if re := d.GetValidationRegex(); re != "" {
			if _, err := regexp.Compile(re); err == nil {
				fd.Pattern = re
			}
		}
		v, set := values[d.GetJsonKey()]
		selected := map[string]bool{}
		switch x := v.(type) {
		case string:
			fd.Value = x
		case float64:
			fd.Value = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			fd.Checked = x
		case []any:
			for _, e := range x {
				if str, ok := e.(string); ok {
					selected[str] = true
				}
			}
		}
		if !set && fd.Type == "checkbox" {
			fd.Checked = d.GetDefaultValue() == "true"
		}
		for i, o := range d.GetOptions() {
			if i == maxOptions {
				break
			}
			fd.Options = append(fd.Options, Option{Label: o.GetLabel(), Value: o.GetValue(), Selected: selected[o.GetValue()] || o.GetValue() == fd.Value})
		}
		out = append(out, fd)
	}
	return out
}

func invalidForm(detail string) error {
	return &changerequests.Error{Status: http.StatusUnprocessableEntity, Slug: "validation-failed", Detail: detail}
}

// values reads a form's fields under prefix back into a JSON object; empty
// optional fields are left out. The plugin's ValidateTarget is the
// authoritative check.
func (s *Server) values(r *http.Request, f *pluginv1.UIForm, prefix string) (map[string]any, error) {
	out := map[string]any{}
	for _, d := range s.descriptors(f) {
		name, raw := prefix+d.GetJsonKey(), strings.TrimSpace(r.PostFormValue(prefix+d.GetJsonKey()))
		switch d.GetFieldType() {
		case pluginv1.UIFieldType_UI_FIELD_TYPE_BOOLEAN:
			out[d.GetJsonKey()] = r.PostFormValue(name) == "on"
		case pluginv1.UIFieldType_UI_FIELD_TYPE_MULTISELECT:
			if vs := r.PostForm[name]; len(vs) > 0 {
				out[d.GetJsonKey()] = vs
			}
		case pluginv1.UIFieldType_UI_FIELD_TYPE_NUMBER:
			if raw == "" {
				continue
			}
			n, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				return nil, invalidForm(d.GetLabel() + ": not a number")
			}
			out[d.GetJsonKey()] = n
		default:
			if raw != "" {
				out[d.GetJsonKey()] = raw
			}
		}
	}
	return out, nil
}

// LevelBlock is one access level's inputs and the button that adds the next.
type LevelBlock struct {
	Platform    string
	Index       int
	Name        string
	Description string
	Grants      []Field
	Next        int
}

// PlatformFields are a platform's forms: the definition and the levels.
type PlatformFields struct {
	Platform   string
	Definition []Field
	Levels     []LevelBlock
	Next       int
}

// platformFields builds the forms of platform with a target's values.
func (s *Server) platformFields(ctx context.Context, platform string, t *targets.Target) (*PlatformFields, error) {
	ui, err := s.Plugins.UISchemas(ctx, platform)
	if err != nil {
		return nil, err
	}
	pf := &PlatformFields{Platform: platform}
	def := map[string]any{}
	levels := []targets.AccessLevel{{}}
	if t != nil {
		_ = json.Unmarshal(t.Definition, &def)
		if len(t.AccessLevels) > 0 {
			levels = t.AccessLevels
		}
	}
	pf.Definition = s.fields(ui.GetTargetDefinition(), "def.", def)
	for i, l := range levels {
		grants := map[string]any{}
		_ = json.Unmarshal(l.Grants, &grants)
		pf.Levels = append(pf.Levels, LevelBlock{Platform: platform, Index: i, Name: l.Name, Description: l.Description,
			Grants: s.fields(ui.GetAccessLevelGrants(), "level."+strconv.Itoa(i)+".grant.", grants)})
	}
	pf.Next = len(pf.Levels)
	return pf, nil
}

// configured reports whether name is a platform of server.yaml.
func (s *Server) configured(name string) bool {
	_, ok := s.Targets.Rules.Platforms[name]
	return ok
}

// platformFieldsFragment is GET /ui/platforms/{name}/fields (and
// /ui/platforms/fields?platform=, which the platform select can call): the
// definition and the first level's forms, or with ?level=N one more level
// (§7.4, from GetUISchemas).
func (s *Server) platformFieldsFragment(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	name := r.PathValue("name")
	if name == "" {
		name = r.URL.Query().Get("platform") // GET /ui/platforms/fields from the form's platform select
	}
	if !s.configured(name) {
		s.alert(w, r, http.StatusNotFound, "No such platform.")
		return
	}
	pf, err := s.platformFields(r.Context(), name, nil)
	if err != nil {
		s.Logger.Error("ui: UI schemas", "platform", name, "error", err)
		s.alert(w, r, http.StatusServiceUnavailable, "The platform's plugin cannot be reached.")
		return
	}
	if v := r.URL.Query().Get("level"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 32 {
			s.alert(w, r, http.StatusUnprocessableEntity, "Too many access levels.")
			return
		}
		b := pf.Levels[0]
		b.Index, b.Next = n, n+1
		ui, _ := s.Plugins.UISchemas(r.Context(), name)
		b.Grants = s.fields(ui.GetAccessLevelGrants(), "level."+strconv.Itoa(n)+".grant.", nil)
		s.fragment(w, r, http.StatusOK, "level-block", b)
		return
	}
	s.fragment(w, r, http.StatusOK, "platform-fields", pf)
}

// TargetForm is the data of the target form, new or edit.
type TargetForm struct {
	Edit      bool
	Revision  int64
	Target    targets.Target
	Platforms []string
	Fields    *PlatformFields
	Flows     string // JSON
	Labels    string
	Contacts  string
	VisibleTo string
	Reapplied []*bindings.View // for an update: the bindings a change re-applies
}

func (s *Server) targetNewForm(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	p := s.frame(r, "Publish a target", "/ui/targets")
	p.Content = TargetForm{Platforms: slices.Sorted(maps.Keys(s.Targets.Rules.Platforms)), Target: targets.Target{Visibility: sources.Visibility{Mode: "PRIVATE"}},
		Flows: "[]"}
	s.page(w, r, http.StatusOK, "target-form", p)
}

func (s *Server) targetEditForm(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	ctx, c := r.Context(), session(r).Caller()
	v, err := s.Targets.Get(ctx, c, r.PathValue("name"))
	var f TargetForm
	if err == nil {
		f = TargetForm{Edit: true, Revision: v.Metadata.Revision, Target: v.Target, VisibleTo: strings.Join(v.Visibility.VisibleTo, "\n")}
		f.Fields, err = s.platformFields(ctx, v.Metadata.Platform, &v.Target)
	}
	if err == nil {
		f.Reapplied, _, err = s.Bindings.List(ctx, c, bindings.Filter{Target: v.Metadata.Name, Limit: 200})
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	b, _ := json.MarshalIndent(v.NetworkFlows, "", "  ")
	f.Flows = string(b)
	for _, k := range slices.Sorted(maps.Keys(v.Labels)) {
		f.Labels += k + "=" + v.Labels[k] + "\n"
	}
	for _, ct := range v.Contacts {
		f.Contacts += ct.Name + " <" + ct.Email + ">\n"
	}
	p := s.frame(r, "Edit "+v.Metadata.Name, "/ui/targets")
	p.Content = f
	s.page(w, r, http.StatusOK, "target-form", p)
}

// targetOf reads the form into a target body, with the platform's forms.
func (s *Server) targetOf(r *http.Request, name string) (*targets.Target, error) {
	if err := r.ParseForm(); err != nil {
		return nil, invalidForm("the form cannot be read")
	}
	t := &targets.Target{Kind: "Target", Metadata: targets.Metadata{Name: name, Scope: strings.TrimSpace(r.PostFormValue("scope")),
		Platform: r.PostFormValue("platform")}, DisplayName: strings.TrimSpace(r.PostFormValue("displayName")),
		Description: strings.TrimSpace(r.PostFormValue("description")), DocumentationURL: strings.TrimSpace(r.PostFormValue("documentationUrl")),
		Contacts:   contacts(r.PostFormValue("contacts")),
		Visibility: sources.Visibility{Mode: r.PostFormValue("visibility"), VisibleTo: lines(r.PostFormValue("visibleTo"))}}
	if t.Metadata.Name == "" {
		t.Metadata.Name = strings.TrimSpace(r.PostFormValue("name"))
	}
	labels, err := pairs(r.PostFormValue("labels"))
	if err != nil {
		return nil, err
	}
	if len(labels) > 0 {
		t.Labels = labels
	}
	if raw := strings.TrimSpace(r.PostFormValue("networkFlows")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &t.NetworkFlows); err != nil {
			return nil, invalidForm("network flows: not a JSON array of flows")
		}
	}
	if t.NetworkFlows == nil {
		t.NetworkFlows = []flows.Flow{}
	}
	if !s.configured(t.Metadata.Platform) {
		return nil, invalidForm("choose a configured platform")
	}
	ui, err := s.Plugins.UISchemas(r.Context(), t.Metadata.Platform)
	if err != nil {
		s.Logger.Error("ui: UI schemas", "platform", t.Metadata.Platform, "error", err)
		return nil, &changerequests.Error{Status: http.StatusServiceUnavailable, Slug: "unavailable", Detail: "The platform's plugin cannot be reached."}
	}
	def, err := s.values(r, ui.GetTargetDefinition(), "def.")
	if err != nil {
		return nil, err
	}
	t.Definition, _ = json.Marshal(def)
	var indices []int
	for key := range r.PostForm {
		if rest, ok := strings.CutPrefix(key, "level."); ok {
			if n, name, ok := strings.Cut(rest, "."); ok && name == "name" {
				if i, err := strconv.Atoi(n); err == nil {
					indices = append(indices, i)
				}
			}
		}
	}
	slices.Sort(indices)
	for _, i := range indices {
		p := "level." + strconv.Itoa(i) + "."
		lname := strings.TrimSpace(r.PostFormValue(p + "name"))
		if lname == "" {
			continue // an empty block added by mistake
		}
		grants, err := s.values(r, ui.GetAccessLevelGrants(), p+"grant.")
		if err != nil {
			return nil, err
		}
		g, _ := json.Marshal(grants)
		t.AccessLevels = append(t.AccessLevels, targets.AccessLevel{Name: lname, Description: strings.TrimSpace(r.PostFormValue(p + "description")), Grants: g})
	}
	return t, nil
}

// TargetCheck is the governance outcome of the target form.
type TargetCheck struct {
	Governance any
	Error      string
}

// targetPreview is POST /ui/targets/preview: the governance outcome of the
// target's name, platform and scope (internal/preview).
func (s *Server) targetPreview(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	body, _ := json.Marshal(targets.Target{Kind: "Target", Metadata: targets.Metadata{Name: strings.TrimSpace(r.PostFormValue("name")),
		Scope: strings.TrimSpace(r.PostFormValue("scope")), Platform: r.PostFormValue("platform")}})
	var d TargetCheck
	e, err := s.preview().Evaluate(r.Context(), session(r).Caller(), body)
	if err != nil {
		d.Error = message(err)
	} else {
		d.Governance = e
	}
	s.fragment(w, r, http.StatusOK, "target-check", d)
}

// targetSubmit is POST /ui/targets and PUT /ui/targets/{name}.
func (s *Server) targetSubmit(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	t, err := s.targetOf(r, name)
	if err != nil {
		s.filed(w, r, nil, err, "")
		return
	}
	body := map[string]any{}
	raw, _ := json.Marshal(t)
	_ = json.Unmarshal(raw, &body)
	ctx, c := r.Context(), session(r).Caller()
	var cr *changerequests.Request
	if name != "" {
		rev, perr := strconv.ParseInt(r.PostFormValue("expectedRevision"), 10, 64)
		if perr != nil {
			s.alert(w, r, http.StatusUnprocessableEntity, "The form lost its revision: reload it.")
			return
		}
		body["expectedRevision"] = rev
		b, _ := json.Marshal(body)
		cr, err = s.Targets.Update(ctx, c, name, b)
	} else {
		b, _ := json.Marshal(body)
		cr, err = s.Targets.Create(ctx, c, b)
	}
	s.filed(w, r, cr, err, "/ui/targets/"+t.Metadata.Name)
}

// targetState is POST /ui/targets/{name}/{op} and
// /ui/targets/{name}/access-levels/{level}/{op}.
func (s *Server) targetState(w http.ResponseWriter, r *http.Request) {
	name, level, op := r.PathValue("name"), r.PathValue("level"), r.PathValue("op")
	if op != "deprecate" && op != "reactivate" && op != "retire" {
		http.NotFound(w, r)
		return
	}
	rev, err := strconv.ParseInt(r.PostFormValue("expectedRevision"), 10, 64)
	if err != nil {
		s.alert(w, r, http.StatusUnprocessableEntity, "The page lost its revision: reload it.")
		return
	}
	ctx, c := r.Context(), session(r).Caller()
	var cr *changerequests.Request
	if level != "" {
		cr, err = s.Targets.SetLevelState(ctx, c, name, level, op, rev, "", nil)
	} else {
		cr, err = s.Targets.SetState(ctx, c, name, op, rev, "", nil)
	}
	target := "/ui/targets/" + name
	if op == "retire" && level == "" {
		target = "/ui/targets"
	}
	s.filed(w, r, cr, err, target)
}

// revokeOn is POST /ui/targets/{name}/bindings/revoke: one revocation per
// binding of a source, or of a source scope (containment, AC-79); the
// queue then shows the requests.
// shortcut: a binding whose revocation failed is reported only in the log; show the failures on the target page if operators need them.
func (s *Server) revokeOn(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	out, err := s.Bindings.RevokeOn(r.Context(), session(r).Caller(), name, strings.TrimSpace(r.PostFormValue("source")),
		strings.TrimSpace(r.PostFormValue("sourceScope")), strings.TrimSpace(r.PostFormValue("comment")), "")
	if err == nil && len(out) == 0 {
		err = invalidForm("No binding of " + name + " matches.")
	}
	filed := 0
	for _, o := range out {
		if o.Error != nil {
			s.Logger.Warn("ui: a bulk revocation failed", "binding", o.Binding, "error", o.Error)
			continue
		}
		filed++
	}
	var e *changerequests.Error
	switch {
	case errors.As(err, &e):
		s.alert(w, r, e.Status, e.Detail)
	case err != nil:
		s.fail(w, r, err)
	case filed == 0:
		s.alert(w, r, http.StatusConflict, "No revocation could be filed; see the bindings' pending changes.")
	default:
		redirect(w, "/ui/change-requests?status=PENDING")
	}
}
