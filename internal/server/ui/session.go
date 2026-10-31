package ui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/dihedron/ligo/internal/adminauth"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/theme"
	"github.com/jackc/pgx/v5"
)

// Directory is the LDAP directory of admin_auth (adminauth.LDAP).
type Directory interface {
	Authenticate(ctx context.Context, username, password string) (authz.Principal, error)
	Lookup(ctx context.Context, username string) (authz.Principal, error)
}

const (
	sessionCookie  = "__Host-ligo_session"
	preloginCookie = "__Host-ligo_prelogin"
	themeCookie    = "__Host-ligo_theme"
	actor          = "system:admin-ui"
)

// Session is a signed-in user's session (§7.3).
type Session struct {
	Username string
	Grants   authz.Grants
	CSRF     string
}

// Caller is the session's principal and grants, for the services.
func (s *Session) Caller() changerequests.Caller {
	return changerequests.Caller{Principal: authz.Principal{Name: s.Username}, Grants: s.Grants}
}

type sessionKey struct{}

func session(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionKey{}).(*Session)
	return s
}

// token is 32 random bytes, hex: session tokens, CSRF tokens and the
// pre-login value.
func token() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

func hash(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func equal(a, b string) bool { return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// sameOrigin: the request comes from the UI's own pages (§7.3 rule 4).
func (s *Server) sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	origin := r.Header.Get("Origin")
	return origin != "" && origin == s.Listener.ExternalOrigin
}

func clientIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// unauthenticated sends the browser to the login page: a navigation is
// redirected, an htmx request answers HX-Redirect (§7.4).
func unauthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "" {
		redirect(w, "/ui/login")
		return
	}
	http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
}

// audited writes one SESSION_* entry in its own transaction.
func (s *Server) audited(ctx context.Context, action, user string, snapshot map[string]any) {
	snap, _ := json.Marshal(snapshot)
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Entry{Action: action, Actor: actor, Snapshot: snap})
		return err
	})
	if err != nil {
		s.Logger.Error("ui: audit", "action", action, "user", user, "error", err)
	}
}

// loginPage is GET /ui/login: the pre-login cookie and the same value in
// the form, for the double-submit check (§7.3 rule 1).
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	v := token()
	http.SetCookie(w, cookie(preloginCookie, v, 600))
	s.page(w, r, http.StatusOK, "login", Page{Title: "Sign in", Content: map[string]string{"Prelogin": v}})
}

// login is POST /ui/login: the double-submit check, the failed-login
// limits, LDAP, then a new session (§7.3 rules 1, 2 and 6).
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(preloginCookie)
	if !s.sameOrigin(r) || err != nil || !equal(c.Value, r.PostFormValue("prelogin")) {
		s.alert(w, r, http.StatusForbidden, "The sign-in form has expired. Reload the page and try again.")
		return
	}
	user, password, ip := r.PostFormValue("username"), r.PostFormValue("password"), clientIP(r)
	if s.Logins.Limited(ip, user) {
		w.Header().Set("Retry-After", "60")
		s.alert(w, r, http.StatusTooManyRequests, "Too many failed sign-ins. Wait a minute and try again.")
		return
	}
	p, err := s.LDAP.Authenticate(r.Context(), user, password)
	var grants authz.Grants
	if err == nil {
		if grants = s.Authz.For(p); len(grants) == 0 {
			err = adminauth.ErrInvalidCredentials // no role is no access, and looks the same
		}
	}
	switch {
	case errors.Is(err, adminauth.ErrInvalidCredentials):
		s.Logins.Failed(ip, user)
		if len(user) > 255 {
			user = user[:255]
		}
		s.audited(r.Context(), "SESSION_LOGIN_FAILED", user, map[string]any{"username": user, "remote": ip, "path": r.URL.Path})
		s.alert(w, r, http.StatusUnauthorized, "The username or password is not valid.")
		return
	case err != nil:
		s.Logger.Error("ui: login", "error", err)
		s.alert(w, r, http.StatusServiceUnavailable, "The directory cannot be reached. Try again later.")
		return
	}
	t, err := s.create(r.Context(), user, grants, ip, "SESSION_LOGIN")
	if err != nil {
		s.Logger.Error("ui: create a session", "error", err)
		s.alert(w, r, http.StatusServiceUnavailable, "The session cannot be created. Try again later.")
		return
	}
	http.SetCookie(w, cookie(sessionCookie, t, 0))
	http.SetCookie(w, cookie(preloginCookie, "", -1))
	redirect(w, "/ui/bindings")
}

// create stores a new session, only the token's SHA-256, and audits action
// with it; it returns the token for the cookie.
func (s *Server) create(ctx context.Context, user string, grants authz.Grants, ip, action string) (string, error) {
	t := token()
	roles, err := json.Marshal(grants)
	if err != nil {
		return "", err
	}
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO admin_sessions (token_sha256, username, roles, csrf_token, client_ip, expires_at)
			VALUES ($1, $2, $3, $4, nullif($5, '')::inet, now() + make_interval(secs => $6))`,
			hash(t), user, roles, token(), ip, s.Listener.Session.AbsoluteTimeout.Seconds()); err != nil {
			return err
		}
		snap, _ := json.Marshal(map[string]any{"username": user, "remote": ip, "roles": grants})
		_, err := audit.Append(ctx, tx, audit.Entry{Action: action, Actor: user, Snapshot: snap})
		return err
	})
	return t, err
}

// revoke ends the session of hash, auditing action.
func (s *Server) revoke(ctx context.Context, h, user, action string) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE admin_sessions SET revoked_at = now() WHERE token_sha256 = $1 AND revoked_at IS NULL`, h); err != nil {
			return err
		}
		snap, _ := json.Marshal(map[string]any{"username": user})
		_, err := audit.Append(ctx, tx, audit.Entry{Action: action, Actor: actor, Snapshot: snap})
		return err
	})
}

// authed requires a live session (§7.3 rules 3 and 4): not revoked, within
// its absolute and idle timeouts, its roles re-checked against LDAP every
// authz_recheck_interval, the token rotated when they change; non-GET
// requests carry the CSRF token and come from the UI's own pages.
func (s *Server) authed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			unauthenticated(w, r)
			return
		}
		ctx, h := r.Context(), hash(c.Value)
		ss := s.Listener.Session
		var sess Session
		var roles []byte
		var dead, idle, stale bool
		err = s.DB.QueryRow(ctx, `SELECT username, roles, csrf_token, revoked_at IS NOT NULL OR expires_at <= now(),
			last_seen_at < now() - make_interval(secs => $2), authz_checked_at < now() - make_interval(secs => $3)
			FROM admin_sessions WHERE token_sha256 = $1`, h, ss.IdleTimeout.Seconds(), ss.AuthzRecheckInterval.Seconds()).
			Scan(&sess.Username, &roles, &sess.CSRF, &dead, &idle, &stale)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && dead {
			http.SetCookie(w, cookie(sessionCookie, "", -1))
			unauthenticated(w, r)
			return
		}
		if err != nil {
			s.Logger.Error("ui: session", "error", err)
			s.alert(w, r, http.StatusServiceUnavailable, "The session cannot be read. Try again later.")
			return
		}
		if idle {
			if err := s.revoke(ctx, h, sess.Username, "SESSION_REVOKED"); err != nil {
				s.Logger.Error("ui: revoke an idle session", "error", err)
			}
			http.SetCookie(w, cookie(sessionCookie, "", -1))
			unauthenticated(w, r)
			return
		}
		if err := json.Unmarshal(roles, &sess.Grants); err != nil {
			s.Logger.Error("ui: session roles", "error", err)
			s.alert(w, r, http.StatusServiceUnavailable, "The session cannot be read. Try again later.")
			return
		}
		if stale {
			ok, err := s.recheck(w, r, h, &sess)
			if err != nil {
				s.Logger.Error("ui: re-check the session's roles", "user", sess.Username, "error", err)
				s.alert(w, r, http.StatusServiceUnavailable, "The directory cannot be reached. Try again later.")
				return
			}
			if !ok {
				http.SetCookie(w, cookie(sessionCookie, "", -1))
				unauthenticated(w, r)
				return
			}
		} else if _, err := s.DB.Exec(ctx, `UPDATE admin_sessions SET last_seen_at = now() WHERE token_sha256 = $1`, h); err != nil {
			s.Logger.Error("ui: session last seen", "error", err)
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && (!equal(r.Header.Get("X-CSRF-Token"), sess.CSRF) || !s.sameOrigin(r)) {
			s.alert(w, r, http.StatusForbidden, "The request was refused: reload the page and try again.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, sessionKey{}, &sess)))
	})
}

// recheck reads the user's groups again (§7.3 rule 3): no role left
// revokes the session (AC-17); other roles rotate its token, so a session
// never carries privileges it was not issued with.
func (s *Server) recheck(w http.ResponseWriter, r *http.Request, h string, sess *Session) (bool, error) {
	ctx := r.Context()
	p, err := s.LDAP.Lookup(ctx, sess.Username)
	if err != nil && !errors.Is(err, adminauth.ErrInvalidCredentials) {
		return false, err
	}
	var grants authz.Grants
	if err == nil {
		grants = s.Authz.For(p)
	}
	if len(grants) == 0 {
		return false, s.revoke(ctx, h, sess.Username, "SESSION_REVOKED")
	}
	before, _ := json.Marshal(sess.Grants)
	after, _ := json.Marshal(grants)
	if string(before) == string(after) {
		_, err := s.DB.Exec(ctx, `UPDATE admin_sessions SET authz_checked_at = now(), last_seen_at = now() WHERE token_sha256 = $1`, h)
		return true, err
	}
	t, err := s.create(ctx, sess.Username, grants, clientIP(r), "SESSION_LOGIN")
	if err != nil {
		return false, err
	}
	if err := s.revoke(ctx, h, sess.Username, "SESSION_REVOKED"); err != nil {
		return false, err
	}
	if err := s.DB.QueryRow(ctx, `SELECT csrf_token FROM admin_sessions WHERE token_sha256 = $1`, hash(t)).Scan(&sess.CSRF); err != nil {
		return false, err
	}
	sess.Grants = grants
	http.SetCookie(w, cookie(sessionCookie, t, 0))
	return true, nil
}

// logout is POST /ui/logout (§7.3 rule 5).
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(sessionCookie) // authed checked it
	if err := s.revoke(r.Context(), hash(c.Value), session(r).Username, "SESSION_LOGOUT"); err != nil {
		s.Logger.Error("ui: logout", "error", err)
		s.alert(w, r, http.StatusServiceUnavailable, "The session cannot be ended. Try again.")
		return
	}
	http.SetCookie(w, cookie(sessionCookie, "", -1))
	redirect(w, "/ui/login")
}

// preference is POST /ui/preferences/theme: the color mode cookie, read
// only by the server (§7.6).
func (s *Server) preference(w http.ResponseWriter, r *http.Request) {
	mode := r.PostFormValue("mode")
	if !slices.Contains(theme.Modes, mode) {
		s.alert(w, r, http.StatusUnprocessableEntity, "Unknown appearance.")
		return
	}
	http.SetCookie(w, cookie(themeCookie, mode, int((365*24*time.Hour).Seconds())))
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

// frame is the layout's data for a signed-in page: the CSRF token, the
// user, the navigation and the maintenance banner.
func (s *Server) frame(r *http.Request, title, current string) Page {
	sess := session(r)
	p := Page{Title: title, CSRF: sess.CSRF, User: sess.Username}
	for _, n := range []NavItem{{Path: "/ui/bindings", Label: "Bindings"}, {Path: "/ui/catalog", Label: "Catalog"},
		{Path: "/ui/sources", Label: "Sources"}, {Path: "/ui/targets", Label: "Targets"}, {Path: "/ui/change-requests", Label: "Change requests"},
		{Path: "/ui/platforms", Label: "Platforms"}} {
		n.Current = n.Path == current
		p.Nav = append(p.Nav, n)
	}
	var on bool
	var reason string
	if err := s.DB.QueryRow(r.Context(), `SELECT maintenance_mode, coalesce(maintenance_reason, '') FROM system_settings`).Scan(&on, &reason); err != nil {
		s.Logger.Error("ui: maintenance mode", "error", err)
	} else if on {
		p.Maintenance = &Maintenance{Reason: reason}
	}
	return p
}
