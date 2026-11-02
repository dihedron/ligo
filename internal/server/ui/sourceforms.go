package ui

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/preview"
	"github.com/dihedron/ligo/internal/sources"
)

// lines splits a textarea into its non-empty, trimmed lines.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// pairs reads key=value lines; a line without = is an error.
func pairs(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, l := range lines(s) {
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, &changerequests.Error{Status: http.StatusUnprocessableEntity, Slug: "validation-failed", Detail: "labels: " + l + " is not key=value"}
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

// contacts reads "Name <email>" lines.
func contacts(s string) []sources.Contact {
	var out []sources.Contact
	for _, l := range lines(s) {
		name, email, _ := strings.Cut(l, "<")
		out = append(out, sources.Contact{Name: strings.TrimSpace(name), Email: strings.TrimSuffix(strings.TrimSpace(email), ">")})
	}
	return out
}

// SourceForm is the data of the source form, new or edit.
type SourceForm struct {
	Edit         bool
	Revision     int64
	Source       sources.Source
	TrustDomains []string
	Samples      string // one per line
	Labels       string // key=value per line
	Contacts     string // Name <email> per line
	VisibleTo    string
}

func (s *Server) trustDomains() []string { return slices.Sorted(maps.Keys(s.Sources.Rules.Extractors)) }

func (s *Server) sourceNewForm(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	p := s.frame(r, "Register a source", "/ui/sources")
	p.Content = SourceForm{TrustDomains: s.trustDomains(), Source: sources.Source{Visibility: sources.Visibility{Mode: "PRIVATE"}}}
	s.page(w, r, http.StatusOK, "source-form", p)
}

func (s *Server) sourceEditForm(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	v, err := s.Sources.Get(r.Context(), session(r).Caller(), r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := SourceForm{Edit: true, Revision: v.Metadata.Revision, Source: v.Source, TrustDomains: s.trustDomains(),
		Samples: strings.Join(v.Identity.SampleSPIFFEIDs, "\n"), VisibleTo: strings.Join(v.Visibility.VisibleTo, "\n")}
	for _, k := range slices.Sorted(maps.Keys(v.Labels)) {
		f.Labels += k + "=" + v.Labels[k] + "\n"
	}
	for _, c := range v.Contacts {
		f.Contacts += c.Name + " <" + c.Email + ">\n"
	}
	p := s.frame(r, "Edit "+v.Metadata.Name, "/ui/sources")
	p.Content = f
	s.page(w, r, http.StatusOK, "source-form", p)
}

// sourceOf reads the form into a source body.
func sourceOf(r *http.Request) (sources.Source, error) {
	src := sources.Source{Kind: "Source", Metadata: sources.Metadata{Name: strings.TrimSpace(r.PostFormValue("name"))},
		Identity: sources.Identity{TrustDomain: r.PostFormValue("trustDomain"), SVIDRegex: strings.TrimSpace(r.PostFormValue("svidRegex")),
			SampleSPIFFEIDs: lines(r.PostFormValue("samples"))},
		DisplayName: strings.TrimSpace(r.PostFormValue("displayName")), Description: strings.TrimSpace(r.PostFormValue("description")),
		Contacts:   contacts(r.PostFormValue("contacts")),
		Visibility: sources.Visibility{Mode: r.PostFormValue("visibility"), VisibleTo: lines(r.PostFormValue("visibleTo"))}}
	labels, err := pairs(r.PostFormValue("labels"))
	if len(labels) > 0 {
		src.Labels = labels
	}
	return src, err
}

// SourceCheck is the regex tester's fragment: the tester's result and the
// governance outcome of the source (§7.4).
type SourceCheck struct {
	Test       *sources.TestResult
	Governance *preview.Evaluation
	Error      string // why the governance outcome is missing
}

// sourceTest is POST /ui/sources/test: the same tester and dry run as the
// API (Appendix A, scope, samples, overlaps, narrowing with a witness).
func (s *Server) sourceTest(w http.ResponseWriter, r *http.Request) {
	if !s.readable(w, r) {
		return
	}
	src, _ := sourceOf(r) // labels do not matter here
	ctx, c := r.Context(), session(r).Caller()
	var d SourceCheck
	var err error
	req := sources.TestRequest{TrustDomain: src.Identity.TrustDomain, SVIDRegex: src.Identity.SVIDRegex, SPIFFEIDs: src.Identity.SampleSPIFFEIDs}
	if r.PostFormValue("expectedRevision") != "" {
		req.CurrentSource = src.Metadata.Name
	}
	if d.Test, err = s.Sources.Test(ctx, c, req); err != nil {
		s.alert(w, r, http.StatusUnprocessableEntity, message(err))
		return
	}
	if d.Test.Valid {
		body, _ := json.Marshal(src)
		if d.Governance, err = s.preview().Evaluate(ctx, c, body); err != nil {
			d.Error = message(err)
		}
	}
	s.fragment(w, r, http.StatusOK, "source-check", d)
}

func (s *Server) preview() *preview.Evaluator {
	return &preview.Evaluator{Sources: s.Sources, Targets: s.Targets, Bindings: s.Bindings, Requests: s.Requests}
}

// message is a service error's detail, or a generic sentence.
func message(err error) string {
	var e *changerequests.Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return "The request cannot be checked now."
}

// filed answers a filed change: to the resource once applied, else to the
// change request, with HX-Redirect (§7.4); refusals land in the form.
func (s *Server) filed(w http.ResponseWriter, r *http.Request, cr *changerequests.Request, err error, resource string) {
	var e *changerequests.Error
	switch {
	case errors.As(err, &e):
		s.alert(w, r, e.Status, e.Detail)
	case err != nil:
		s.fail(w, r, err)
	case cr.Status == "APPLIED" && resource != "":
		redirect(w, resource)
	default:
		redirect(w, "/ui/change-requests/"+cr.ID.String())
	}
}

// sourceSubmit is POST /ui/sources and PUT /ui/sources/{name}.
func (s *Server) sourceSubmit(w http.ResponseWriter, r *http.Request) {
	src, err := sourceOf(r)
	if err != nil {
		s.filed(w, r, nil, err, "")
		return
	}
	body := map[string]any{}
	raw, _ := json.Marshal(src)
	_ = json.Unmarshal(raw, &body)
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
		cr, err = s.Sources.Update(ctx, c, name, b)
		src.Metadata.Name = name
	} else {
		b, _ := json.Marshal(body)
		cr, err = s.Sources.Create(ctx, c, b)
	}
	s.filed(w, r, cr, err, "/ui/sources/"+src.Metadata.Name)
}

// sourceState is POST /ui/sources/{name}/{deprecate,reactivate,retire}.
func (s *Server) sourceState(w http.ResponseWriter, r *http.Request) {
	name, op := r.PathValue("name"), r.PathValue("op")
	if op != "deprecate" && op != "reactivate" && op != "retire" {
		http.NotFound(w, r)
		return
	}
	rev, err := strconv.ParseInt(r.PostFormValue("expectedRevision"), 10, 64)
	if err != nil {
		s.alert(w, r, http.StatusUnprocessableEntity, "The page lost its revision: reload it.")
		return
	}
	cr, err := s.Sources.SetState(r.Context(), session(r).Caller(), name, op, rev, "", nil)
	target := "/ui/sources/" + name
	if op == "retire" {
		target = "/ui/sources"
	}
	s.filed(w, r, cr, err, target)
}
