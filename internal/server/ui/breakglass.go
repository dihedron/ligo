package ui

import (
	"encoding/json"
	"errors"
	"net/http"
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
// look targets up; for a binding the user can read, they come prefilled.
type BreakGlassForm struct {
	Operation                            string // CREATE, UPDATE or DELETE
	Name, Source, Target, Level, Purpose string
	Parameters                           string // JSON object
	Revision                             string
	TrustDomains                         []string
	MinJustification                     int
}

// breakGlassMember reports a break_glass grant on any scope: the form and
// its navigation entry are for those only.
func breakGlassMember(gs authz.Grants) bool {
	return slices.ContainsFunc(gs, func(g authz.Grant) bool { return g.Role == config.RoleBreakGlass })
}

// breakGlassForm is GET /ui/break-glass/new-form[?operation=…&name=…].
func (s *Server) breakGlassForm(w http.ResponseWriter, r *http.Request) {
	sess := session(r)
	if !breakGlassMember(sess.Grants) {
		s.fail(w, r, &changerequests.Error{Status: http.StatusForbidden, Slug: "forbidden", Detail: "Break-glass is for members of a break-glass group."})
		return
	}
	q := r.URL.Query()
	f := BreakGlassForm{Operation: q.Get("operation"), Name: q.Get("name"), Target: q.Get("target"), TrustDomains: s.trustDomains(),
		MinJustification: s.Config.BreakGlass.MinJustificationLength}
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

// breakGlassSubmit is POST /ui/break-glass: the password is checked again by
// an LDAP bind, which also reads the groups afresh, and the change is applied
// at once by the service (§7.2.3 "Break-glass operations"). A wrong password
// counts and is audited as a failed sign-in.
func (s *Server) breakGlassSubmit(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ip := session(r), r.Context(), clientIP(r)
	if !breakGlassMember(sess.Grants) {
		s.alert(w, r, http.StatusForbidden, "Break-glass is for members of a break-glass group.")
		return
	}
	if s.Logins.Limited(ip, sess.Username) {
		w.Header().Set("Retry-After", "60")
		s.alert(w, r, http.StatusTooManyRequests, "Too many failed sign-ins. Wait a minute and try again.")
		return
	}
	p, err := s.LDAP.Authenticate(ctx, sess.Username, r.PostFormValue("password"))
	switch {
	case errors.Is(err, adminauth.ErrInvalidCredentials):
		s.Logins.Failed(ip, sess.Username)
		s.audited(ctx, "SESSION_LOGIN_FAILED", sess.Username, map[string]any{"username": sess.Username, "remote": ip, "path": r.URL.Path})
		s.alert(w, r, http.StatusUnauthorized, "The password is not valid.")
		return
	case err != nil:
		s.Logger.Error("ui: break-glass re-authentication", "error", err)
		s.alert(w, r, http.StatusServiceUnavailable, "The directory cannot be reached. Try again later.")
		return
	}
	op, name := r.PostFormValue("operation"), strings.TrimSpace(r.PostFormValue("name"))
	in := map[string]any{"operation": op, "justification": strings.TrimSpace(r.PostFormValue("justification")),
		"incidentReference": strings.TrimSpace(r.PostFormValue("incidentReference")), "ttl": strings.TrimSpace(r.PostFormValue("ttl"))}
	var rev int64
	if op != "CREATE" {
		if rev, err = strconv.ParseInt(r.PostFormValue("expectedRevision"), 10, 64); err != nil {
			s.alert(w, r, http.StatusUnprocessableEntity, "Give the binding's current revision.")
			return
		}
	}
	if op == "DELETE" {
		in["name"], in["expectedRevision"] = name, rev
	} else {
		b := map[string]any{"name": name, "source": strings.TrimSpace(r.PostFormValue("source")), "target": strings.TrimSpace(r.PostFormValue("target")),
			"accessLevel": strings.TrimSpace(r.PostFormValue("accessLevel")), "purpose": strings.TrimSpace(r.PostFormValue("purpose"))}
		if v := strings.TrimSpace(r.PostFormValue("parameters")); v != "" {
			var params map[string]any
			if err := json.Unmarshal([]byte(v), &params); err != nil {
				s.alert(w, r, http.StatusUnprocessableEntity, "The parameters must be a JSON object.")
				return
			}
			b["parameters"] = params
		}
		if op == "UPDATE" {
			b["expectedRevision"] = rev
		}
		if op == "CREATE" && r.PostFormValue("sourceMode") == "inline" {
			src := inlineSource(r)
			b["source"], in["inlineSource"] = src.Metadata.Name, src
		}
		in["binding"] = b
	}
	body, _ := json.Marshal(in)
	cr, err := s.Bindings.BreakGlass(ctx, changerequests.Caller{Principal: p, Grants: s.Authz.For(p)}, body)
	target := "/ui/bindings/" + name
	if op == "DELETE" {
		target = "/ui/bindings"
	}
	s.filed(w, r, cr, err, target)
}
