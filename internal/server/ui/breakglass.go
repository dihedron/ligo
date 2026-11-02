package ui

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dihedron/ligo/internal/adminauth"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
)

// BreakGlassForm is the break-glass form's data (ADR-12, §7.4). The fields
// are plain: break_glass alone reads nothing (§7.2.2), so the form cannot
// look targets up; for a binding the user can read, they come prefilled. A
// refused submission renders the form again with its values (never the
// password), a message on each field at fault and General for the rest.
type BreakGlassForm struct {
	Operation                            string // CREATE, UPDATE or DELETE
	Name, Source, Target, Level, Purpose string
	Parameters                           string // JSON object
	Revision                             string
	Inline                               bool
	InlineSource                         Inline
	Justification, Incident, TTL         string
	TrustDomains                         []string
	MinJustification                     int
	Errors                               map[string]string // by field name
	General                              string
	Applied                              string // the binding just changed, for a user who cannot open it
	Disabled                             bool   // maintenance mode
}

// breakGlassMember reports a break_glass grant on any scope: the form and
// its navigation entry are for those only.
func breakGlassMember(gs authz.Grants) bool {
	return slices.ContainsFunc(gs, func(g authz.Grant) bool { return g.Role == config.RoleBreakGlass })
}

// home is where a user lands after signing in: the break-glass form for
// someone who holds break_glass and no role that reads (§7.2.2).
func home(gs authz.Grants) string {
	if !gs.Viewer() && breakGlassMember(gs) {
		return "/ui/break-glass/new-form"
	}
	return "/ui/bindings"
}

func (s *Server) maintenance(r *http.Request) bool {
	var on bool
	_ = s.DB.QueryRow(r.Context(), `SELECT maintenance_mode FROM system_settings`).Scan(&on)
	return on
}

// breakGlassForm is GET /ui/break-glass/new-form[?operation=…&name=…].
func (s *Server) breakGlassForm(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !breakGlassMember(sess.Grants) {
		s.fail(w, r, &changerequests.Error{Status: http.StatusForbidden, Slug: "forbidden", Detail: "Break-glass is for members of a break-glass group."})
		return
	}
	q := r.URL.Query()
	f := BreakGlassForm{Operation: q.Get("operation"), Name: q.Get("name"), Target: q.Get("target"), TTL: "1h", TrustDomains: s.trustDomains(),
		MinJustification: max(s.Config.BreakGlass.MinJustificationLength, 20), Applied: q.Get("applied"), Disabled: s.maintenance(r)}
	if f.Operation == "" {
		f.Operation = "CREATE"
	}
	if f.Name != "" && sess.Grants.Viewer() {
		if v, err := s.Bindings.Get(r.Context(), sess.Caller(), f.Name); err == nil {
			f.Source, f.Target, f.Level, f.Purpose = v.Source, v.Target, v.AccessLevel, v.Purpose
			f.Parameters, f.Revision = string(v.Parameters), strconv.FormatInt(v.Metadata.Revision, 10)
		}
	}
	p := s.frame(r, "Break glass", "/ui/break-glass/new-form")
	p.Content = f
	s.page(w, r, http.StatusOK, "break-glass", p)
}

// formOf reads the submitted form back, for rendering it again.
func (s *Server) formOf(r *http.Request) BreakGlassForm {
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	return BreakGlassForm{Operation: v("operation"), Name: v("name"), Source: v("source"), Target: v("target"), Level: v("accessLevel"),
		Purpose: v("purpose"), Parameters: v("parameters"), Revision: v("expectedRevision"), Inline: r.PostFormValue("sourceMode") == "inline",
		InlineSource:  Inline{Name: v("inline.name"), TrustDomain: v("inline.trustDomain"), SVIDRegex: v("inline.svidRegex"), Samples: r.PostFormValue("inline.samples")},
		Justification: v("justification"), Incident: v("incidentReference"), TTL: v("ttl"), TrustDomains: s.trustDomains(),
		MinJustification: max(s.Config.BreakGlass.MinJustificationLength, 20), Errors: map[string]string{}, Disabled: s.maintenance(r)}
}

// breakGlassSubmit is POST /ui/break-glass: the password is checked again by
// an LDAP bind, which also reads the groups afresh, and the change is applied
// at once by the service (§7.2.3 "Break-glass operations"). A wrong password
// counts and is audited as a failed sign-in. A refusal renders the form
// again, in place, with the messages on their fields.
func (s *Server) breakGlassSubmit(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ip := session(r), r.Context(), clientIP(r)
	f := s.formOf(r)
	refused := func(status int) { s.fragment(w, r, status, "break-glass-form", f) }
	if !breakGlassMember(sess.Grants) {
		f.General = "Break-glass is for members of a break-glass group."
		refused(http.StatusForbidden)
		return
	}
	if s.Logins.Limited(ip, sess.Username) {
		w.Header().Set("Retry-After", "60")
		f.Errors["password"] = "Too many failed attempts. Wait a minute and try again."
		refused(http.StatusTooManyRequests)
		return
	}
	p, err := s.LDAP.Authenticate(ctx, sess.Username, r.PostFormValue("password"))
	switch {
	case errors.Is(err, adminauth.ErrInvalidCredentials):
		s.Logins.Failed(ip, sess.Username)
		s.audited(ctx, "SESSION_LOGIN_FAILED", sess.Username, map[string]any{"username": sess.Username, "remote": ip, "path": r.URL.Path})
		f.Errors["password"] = "The password is not valid."
		refused(http.StatusUnauthorized)
		return
	case err != nil:
		s.Logger.Error("ui: break-glass re-authentication", "error", err)
		f.General = "The directory cannot be reached. Try again later."
		refused(http.StatusServiceUnavailable)
		return
	}
	in := map[string]any{"operation": f.Operation, "justification": f.Justification, "incidentReference": f.Incident, "ttl": f.TTL}
	var rev int64
	if f.Operation != "CREATE" {
		if rev, err = strconv.ParseInt(f.Revision, 10, 64); err != nil {
			f.Errors["expectedRevision"] = "Give the binding's current revision."
			refused(http.StatusUnprocessableEntity)
			return
		}
	}
	if f.Operation == "DELETE" {
		in["name"], in["expectedRevision"] = f.Name, rev
	} else {
		b := map[string]any{"name": f.Name, "source": f.Source, "target": f.Target, "accessLevel": f.Level, "purpose": f.Purpose}
		if f.Parameters != "" {
			var params map[string]any
			if err := json.Unmarshal([]byte(f.Parameters), &params); err != nil {
				f.Errors["parameters"] = "Must be a JSON object."
				refused(http.StatusUnprocessableEntity)
				return
			}
			b["parameters"] = params
		}
		if f.Operation == "UPDATE" {
			b["expectedRevision"] = rev
		}
		if f.Operation == "CREATE" && f.Inline {
			src := inlineSource(r)
			b["source"], in["inlineSource"] = src.Metadata.Name, src
		}
		in["binding"] = b
	}
	body, _ := json.Marshal(in)
	_, err = s.Bindings.BreakGlass(ctx, changerequests.Caller{Principal: p, Grants: s.Authz.For(p)}, body)
	var e *changerequests.Error
	switch {
	case errors.As(err, &e):
		if len(e.Fields) > 0 {
			maps.Copy(f.Errors, e.Fields)
		} else {
			f.General = e.Detail
		}
		refused(e.Status)
	case err != nil:
		s.Logger.Error("ui: break-glass", "error", err)
		f.General = "The change cannot be applied now. Try again later."
		refused(http.StatusInternalServerError)
	case !sess.Grants.Viewer(): // break_glass alone cannot open the binding: back to the form, which says it is done
		redirect(w, "/ui/break-glass/new-form?applied="+url.QueryEscape(f.Name))
	case f.Operation == "DELETE":
		redirect(w, "/ui/bindings")
	default:
		redirect(w, "/ui/bindings/"+f.Name)
	}
}
