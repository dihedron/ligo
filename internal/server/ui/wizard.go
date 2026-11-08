package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/targets"
)

// Workflows retries and rotates bindings (adminhttp.Workflows).
type Workflows interface {
	Retry(ctx context.Context, bindingID uuid.UUID, actor string) (dbos.WorkflowHandle[string], error)
	Rotate(ctx context.Context, bindingID uuid.UUID, actor string) (dbos.WorkflowHandle[string], error)
}

// SourceChoice is a source the wizard offers, with the policy's outcome.
type SourceChoice struct {
	Name, Jurisdiction string
	Allowed            bool
	Rule               string
}

// Inline is a source the wizard registers with the binding (§7.2.4).
type Inline struct {
	Name, TrustDomain, SVIDRegex, Samples string
}

// Wizard is the binding wizard's state (§7.2.4): each step is rendered
// from the values chosen before it, carried by the form.
type Wizard struct {
	Step         int
	Offer        bool // a target owner offering a binding (scenario 14)
	Targets      []catalog.Target
	Target       *targets.View
	Levels       []targets.AccessLevel
	Level        string
	Sources      []SourceChoice
	Source       string
	UseInline    bool
	Inline       Inline
	TrustDomains []string
	Params       []Field
	Purpose      string
	Labels       string
	ExpiresAt    string // datetime-local, UTC
	Name         string
	Flows        []flows.Flow
}

const wizardSteps = 5 // then submit

// wizard is GET /ui/bindings/wizard: the page, or the next step's form for
// an htmx request; a step whose prerequisites are missing falls back to
// the first one missing.
func (s *Server) wizard(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	q := r.URL.Query()
	ctx, c := r.Context(), session(r).Caller()
	wz := Wizard{Offer: q.Get("offer") == "1", Level: q.Get("accessLevel"), Source: q.Get("source"), UseInline: q.Get("sourceMode") == "inline",
		Inline:  Inline{Name: q.Get("inline.name"), TrustDomain: q.Get("inline.trustDomain"), SVIDRegex: q.Get("inline.svidRegex"), Samples: q.Get("inline.samples")},
		Purpose: q.Get("purpose"), Labels: q.Get("labels"), ExpiresAt: q.Get("expiresAt"), Name: q.Get("name"), TrustDomains: s.trustDomains()}
	wz.Step, _ = strconv.Atoi(q.Get("step"))
	wz.Step = max(1, min(wz.Step, wizardSteps))
	var err error
	if name := q.Get("target"); name != "" {
		if wz.Target, err = s.Targets.Get(ctx, c, name); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	switch {
	case wz.Target == nil:
		wz.Step = 1
		wz.Targets, err = s.Catalog.Targets(ctx, c, catalog.Query{Q: q.Get("q"), Limit: 200})
	case wz.Target.Metadata.State != "ACTIVE":
		s.fail(w, r, &changerequests.Error{Status: http.StatusConflict, Slug: "resource-deprecated", Detail: "The target is deprecated: no new bindings."})
		return
	}
	if err == nil && wz.Target != nil {
		wz.Step = max(wz.Step, 2) // a target chosen before (the catalog's "Request access") starts at the level
		for _, l := range wz.Target.AccessLevels {
			if l.State == "" || l.State == "ACTIVE" {
				wz.Levels = append(wz.Levels, l)
			}
		}
		if !slices.ContainsFunc(wz.Levels, func(l targets.AccessLevel) bool { return l.Name == wz.Level }) {
			wz.Level, wz.Step = "", min(wz.Step, 2)
		}
		wz.Sources, err = s.sourceChoices(ctx, c, wz.Target.Metadata.Name, wz.Offer)
	}
	chosen := wz.Source != "" && slices.ContainsFunc(wz.Sources, func(sc SourceChoice) bool { return sc.Name == wz.Source && sc.Allowed }) ||
		wz.UseInline && wz.Inline.Name != "" && wz.Inline.SVIDRegex != ""
	if wz.Step > 3 && !chosen {
		wz.Step = 3
	}
	if err == nil && wz.Target != nil && wz.Step >= 4 {
		schemas, uerr := s.Plugins.UISchemas(ctx, wz.Target.Metadata.Platform)
		if uerr != nil {
			s.Logger.Error("ui: UI schemas", "platform", wz.Target.Metadata.Platform, "error", uerr)
			s.alert(w, r, http.StatusServiceUnavailable, "The platform's plugin cannot be reached.")
			return
		}
		params := map[string]any{}
		for _, d := range s.descriptors(schemas.GetBindingParameters()) {
			if v := q.Get("param." + d.GetJsonKey()); v != "" {
				params[d.GetJsonKey()] = v
			}
		}
		wz.Params = s.fields(schemas.GetBindingParameters(), "param.", params)
	}
	if err == nil && wz.Step == 5 {
		source := wz.Source
		if wz.UseInline {
			source = wz.Inline.Name
		}
		if wz.Name == "" {
			jurisdiction := ""
			if v, serr := s.Sources.Get(ctx, c, source); serr == nil {
				jurisdiction = v.Metadata.Jurisdiction
			}
			prefix, _ := engine.ResolvePrefix(engine.KindBinding, jurisdiction, s.Bindings.Rules.NamePrefixes)
			wz.Name = engine.SuggestName(source, wz.Target.Metadata.Name, prefix)
		}
		wz.Flows = s.plannedFlows(wz.Target)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if r.Header.Get("HX-Request") != "" {
		s.fragment(w, r, http.StatusOK, "wizard-form", wz)
		return
	}
	p := s.frame(r, "Request access", "/ui/bindings")
	p.Content = wz
	s.page(w, r, http.StatusOK, "wizard", p)
}

// sourceChoices are the user's sources with the policy's outcome for the
// target or, for an offer, the sources visible beyond the user's own.
func (s *Server) sourceChoices(ctx context.Context, c changerequests.Caller, target string, offer bool) ([]SourceChoice, error) {
	var out []SourceChoice
	if offer {
		list, err := s.Catalog.Sources(ctx, c, "", 200)
		for _, src := range list {
			out = append(out, SourceChoice{Name: src.Name, Jurisdiction: src.Jurisdiction, Allowed: true})
		}
		return out, err
	}
	outcomes, err := s.Catalog.Outcomes(ctx, c, target)
	for _, o := range outcomes {
		out = append(out, SourceChoice{Name: o.Source, Jurisdiction: o.SourceJurisdiction, Allowed: o.Allowed, Rule: o.Rule})
	}
	return out, err
}

// plannedFlows are the effective flows a binding to t will have: the
// target's within the platform's allowed endpoints, the platform's, its
// secret store's and ligo's (ADR-16).
func (s *Server) plannedFlows(t *targets.View) []flows.Flow {
	m, rules := t.Metadata, s.Bindings.Rules
	store := ""
	for _, pp := range s.Config.PlatformProviders {
		for _, pl := range pp.Platforms {
			if pl.Name == m.Platform {
				store = pl.SecretStore.Instance
			}
		}
	}
	return flows.Effective(m.Name, rules.Allow[m.Platform].Within(t.NetworkFlows), m.Platform, rules.PlatformFlows[m.Platform], store,
		rules.StoreFlows[store], rules.Ligo)
}

// bindingBody reads the wizard's or the edit form's values into a binding
// body (and the inline source's, for a create).
func (s *Server) bindingBody(r *http.Request, platform string) (map[string]any, error) {
	b := map[string]any{"name": strings.TrimSpace(r.PostFormValue("name")), "target": r.PostFormValue("target"),
		"accessLevel": r.PostFormValue("accessLevel"), "purpose": strings.TrimSpace(r.PostFormValue("purpose"))}
	labels, err := pairs(r.PostFormValue("labels"))
	if err != nil {
		return nil, err
	}
	if len(labels) > 0 {
		b["labels"] = labels
	}
	if v := strings.TrimSpace(r.PostFormValue("expiresAt")); v != "" {
		t, err := time.Parse("2006-01-02T15:04", v)
		if err != nil {
			return nil, invalidForm("expiry: not a date and time")
		}
		b["expiresAt"] = t.UTC()
	}
	schemas, err := s.Plugins.UISchemas(r.Context(), platform)
	if err != nil {
		s.Logger.Error("ui: UI schemas", "platform", platform, "error", err)
		return nil, &changerequests.Error{Status: http.StatusServiceUnavailable, Slug: "unavailable", Detail: "The platform's plugin cannot be reached."}
	}
	params, err := s.values(r, schemas.GetBindingParameters(), "param.")
	if err != nil {
		return nil, err
	}
	b["parameters"] = params
	return b, nil
}

// bindingCreate is POST /ui/bindings: the wizard's submission, with an
// inline source's CREATE when the wizard registers one (§7.2.4).
func (s *Server) bindingCreate(w http.ResponseWriter, r *http.Request) {
	ctx, c := r.Context(), session(r).Caller()
	t, err := s.Targets.Get(ctx, c, r.PostFormValue("target"))
	var body map[string]any
	if err == nil {
		body, err = s.bindingBody(r, t.Metadata.Platform)
	}
	if err == nil {
		if r.PostFormValue("sourceMode") == "inline" {
			src := inlineSource(r)
			body["source"], body["inlineSource"] = src.Metadata.Name, src
		} else {
			body["source"] = r.PostFormValue("source")
		}
	}
	var cr *changerequests.Request
	if err == nil {
		b, _ := json.Marshal(body)
		cr, err = s.Bindings.Create(ctx, c, b)
	}
	name, _ := body["name"].(string)
	s.filed(w, r, cr, err, "/ui/bindings/"+name)
}

// inlineSource is the source the wizard or the break-glass form registers
// with a binding's CREATE, from the inline.* fields.
func inlineSource(r *http.Request) sources.Source {
	return sources.Source{Kind: "Source", Metadata: sources.Metadata{Name: strings.TrimSpace(r.PostFormValue("inline.name"))},
		Identity: sources.Identity{TrustDomain: r.PostFormValue("inline.trustDomain"), SVIDRegex: strings.TrimSpace(r.PostFormValue("inline.svidRegex")),
			SampleSPIFFEIDs: lines(r.PostFormValue("inline.samples"))}, Visibility: sources.Visibility{Mode: "PRIVATE"}}
}

// BindingForm is the binding update form's data.
type BindingForm struct {
	Binding *bindings.View
	Levels  []LevelChoice
	Params  []Field
	Labels  string
	Expires string
}

// LevelChoice is an access level of the binding's target; Unilateral
// marks a level whose privileges are a subset of the current one's, which
// one side may apply alone (ADR-13).
type LevelChoice struct {
	Name       string
	Current    bool
	Unilateral bool
}

func (s *Server) bindingEditForm(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	ctx, c := r.Context(), session(r).Caller()
	v, err := s.Bindings.Get(ctx, c, r.PathValue("name"))
	var t *targets.View
	if err == nil {
		t, err = s.Targets.Get(ctx, c, v.Target)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	schemas, err := s.Plugins.UISchemas(ctx, t.Metadata.Platform)
	if err != nil {
		s.Logger.Error("ui: UI schemas", "platform", t.Metadata.Platform, "error", err)
		s.fail(w, r, &changerequests.Error{Status: http.StatusServiceUnavailable, Slug: "unavailable", Detail: "The platform's plugin cannot be reached."})
		return
	}
	params := map[string]any{}
	_ = json.Unmarshal(v.Parameters, &params)
	f := BindingForm{Binding: v, Params: s.fields(schemas.GetBindingParameters(), "param.", params)}
	var current []string
	for _, l := range t.AccessLevels {
		if l.Name == v.AccessLevel {
			current = l.Privileges
		}
	}
	for _, l := range t.AccessLevels {
		if l.State != "" && l.State != "ACTIVE" && l.Name != v.AccessLevel {
			continue
		}
		subset := l.Name != v.AccessLevel && !slices.ContainsFunc(l.Privileges, func(p string) bool { return !slices.Contains(current, p) })
		f.Levels = append(f.Levels, LevelChoice{Name: l.Name, Current: l.Name == v.AccessLevel, Unilateral: subset})
	}
	for k, val := range v.Labels {
		f.Labels += k + "=" + val + "\n"
	}
	if v.ExpiresAt != nil {
		f.Expires = v.ExpiresAt.UTC().Format("2006-01-02T15:04")
	}
	p := s.frame(r, "Edit "+v.Metadata.Name, "/ui/bindings")
	p.Content = f
	s.page(w, r, http.StatusOK, "binding-form", p)
}

// bindingUpdate is PUT /ui/bindings/{name}.
func (s *Server) bindingUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx, c := r.Context(), session(r).Caller()
	v, err := s.Bindings.Get(ctx, c, name)
	var body map[string]any
	if err == nil {
		var t *targets.View
		if t, err = s.Targets.Get(ctx, c, v.Target); err == nil {
			body, err = s.bindingBody(r, t.Metadata.Platform)
		}
	}
	var cr *changerequests.Request
	if err == nil {
		rev, perr := strconv.ParseInt(r.PostFormValue("expectedRevision"), 10, 64)
		if perr != nil {
			s.alert(w, r, http.StatusUnprocessableEntity, "The form lost its revision: reload it.")
			return
		}
		body["name"], body["source"], body["target"], body["expectedRevision"] = name, v.Source, v.Target, rev
		b, _ := json.Marshal(body)
		cr, err = s.Bindings.Update(ctx, c, name, b)
	}
	s.filed(w, r, cr, err, "/ui/bindings/"+name)
}

// bindingDelete is DELETE /ui/bindings/{name}: a revocation.
func (s *Server) bindingDelete(w http.ResponseWriter, r *http.Request) {
	rev, err := strconv.ParseInt(r.FormValue("expectedRevision"), 10, 64)
	if err != nil {
		s.alert(w, r, http.StatusUnprocessableEntity, "The page lost its revision: reload it.")
		return
	}
	cr, err := s.Bindings.Delete(r.Context(), session(r).Caller(), r.PathValue("name"), rev, "", nil)
	s.filed(w, r, cr, err, "/ui/bindings")
}

// bindingOperate is POST /ui/bindings/{name}/{retry,rotate}, for an
// operator of one of the binding's jurisdictions; it answers the status row.
func (s *Server) bindingOperate(w http.ResponseWriter, r *http.Request) {
	ctx, sess := r.Context(), session(r)
	c := sess.Caller()
	v, err := s.Bindings.Get(ctx, c, r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m := v.Metadata
	if !c.Grants.Operator(m.SourceJurisdiction) && !c.Grants.Operator(m.TargetJurisdiction) && !c.Grants.Operator(m.PlatformJurisdiction) {
		s.alert(w, r, http.StatusForbidden, "An operator role on one of the binding's jurisdictions is required.")
		return
	}
	act := s.Workflows.Retry
	if strings.HasSuffix(r.URL.Path, "/rotate") {
		act = s.Workflows.Rotate
	}
	if _, err := act(ctx, m.ID, c.ID()); err != nil {
		s.fail(w, r, err)
		return
	}
	s.bindingStatus(w, r)
}

// bindingPreview is POST /ui/bindings/governance-preview: the governance
// outcome of the wizard's values (internal/preview).
func (s *Server) bindingPreview(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	body := map[string]any{"resourceType": "BINDING", "name": strings.TrimSpace(r.PostFormValue("name")), "target": r.PostFormValue("target"),
		"accessLevel": r.PostFormValue("accessLevel"), "source": r.PostFormValue("source")}
	if r.PostFormValue("sourceMode") == "inline" {
		body["source"] = map[string]string{"trustDomain": r.PostFormValue("inline.trustDomain"), "svidRegex": strings.TrimSpace(r.PostFormValue("inline.svidRegex"))}
	}
	b, _ := json.Marshal(body)
	var d TargetCheck
	if e, err := s.preview().Evaluate(r.Context(), session(r).Caller(), b); err != nil {
		d.Error = message(err)
	} else {
		d.Governance = e
	}
	s.fragment(w, r, http.StatusOK, "binding-check", d)
}
