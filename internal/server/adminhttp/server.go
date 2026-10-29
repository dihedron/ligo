// Package adminhttp serves the admin REST API on the admin listener
// (§7.2): administrators authenticated by X.509-SVID or, if allowed, LDAP
// Basic credentials; RFC 9457 problems; keyset pagination.
package adminhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/adminauth"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Server is the admin API.
type Server struct {
	Listener config.AdminListener
	LDAP     Directory         // nil: Basic credentials are refused
	Authz    *authz.Authorizer // grants of the principals
	Bundles  x509bundle.Source // the accepted trust domains' bundles, for client SVIDs
	DB       *pgxpool.Pool     // the app pool
	Requests *changerequests.Service
	Bindings *bindings.Service
	Sources  *sources.Service
	Logger   *slog.Logger

	limits limiter
}

// Directory authenticates LDAP users: *adminauth.LDAP.
type Directory interface {
	Authenticate(ctx context.Context, username, password string) (authz.Principal, error)
}

// Handler routes the admin API behind authentication and rate limiting.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.requestRoutes(mux)
	s.opsRoutes(mux)
	s.sourceRoutes(mux)
	return s.middleware(mux)
}

// TLSConfig is the listener's: TLS 1.3, the server certificate from cert,
// and, with client_svid_auth, client X.509-SVIDs verified against the
// accepted trust domains' current bundles at every handshake.
func (s *Server) TLSConfig(cert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: cert,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			c := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: cert}
			if s.Bundles == nil || !s.Listener.ClientSVIDAuth.Enabled {
				return c, nil
			}
			pool := x509.NewCertPool()
			for _, name := range s.Listener.ClientSVIDAuth.AcceptedTrustDomains {
				td, err := spiffeid.TrustDomainFromString(name)
				if err != nil {
					return nil, err
				}
				if b, err := s.Bundles.GetX509BundleForTrustDomain(td); err == nil {
					for _, a := range b.X509Authorities() {
						pool.AddCert(a)
					}
				}
			}
			c.ClientCAs, c.ClientAuth = pool, tls.VerifyClientCertIfGiven
			// the chain must also lead to the bundle of the SVID's own trust
			// domain; VerifyConnection runs on resumed sessions too
			c.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return nil
				}
				_, _, err := x509svid.Verify(cs.PeerCertificates, s.Bundles)
				return err
			}
			return c, nil
		}}
}

type callerKey struct{}

func caller(r *http.Request) changerequests.Caller {
	c, _ := r.Context().Value(callerKey{}).(changerequests.Caller)
	return c
}

// middleware tags the request, authenticates the caller and applies the
// rate limits; session cookies are ignored (§7.2.1).
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewV7().String()
		w.Header().Set("X-Request-Id", id)
		r = r.WithContext(audit.WithRequestID(r.Context(), id))
		start := time.Now()
		c, err := s.authenticate(r)
		switch {
		case errors.Is(err, errLoginLimited):
			w.Header().Set("Retry-After", "60")
			problem(w, http.StatusTooManyRequests, "rate-limited", "too many login attempts")
		case errors.Is(err, adminauth.ErrInvalidCredentials):
			if s.basicAllowed() {
				w.Header().Set("WWW-Authenticate", `Basic realm="ligo"`)
			}
			problem(w, http.StatusUnauthorized, "unauthenticated", "valid credentials are required")
		case err != nil:
			s.Logger.Error("authentication", "request_id", id, "error", err)
			problem(w, http.StatusServiceUnavailable, "unavailable", "the directory cannot be reached")
		case !s.limits.allow("api:"+c.ID(), s.apiRate(c)):
			w.Header().Set("Retry-After", "1")
			problem(w, http.StatusTooManyRequests, "rate-limited", "too many requests")
		default:
			rec := &status{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
			s.Logger.Info("request", "request_id", id, "principal", c.ID(), "method", r.Method, "path", r.URL.Path,
				"status", rec.code, "duration", time.Since(start))
			return
		}
		s.Logger.Info("request refused", "request_id", id, "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	})
}

type status struct {
	http.ResponseWriter
	code int
}

func (s *status) WriteHeader(code int) { s.code = code; s.ResponseWriter.WriteHeader(code) }

var errLoginLimited = errors.New("adminhttp: too many login attempts")

func (s *Server) basicAllowed() bool { return s.Listener.AllowBasicAuth && s.LDAP != nil }

// authenticate prefers a verified client SVID; Basic credentials only if
// allow_basic_auth, within the login rate limits.
func (s *Server) authenticate(r *http.Request) (changerequests.Caller, error) {
	var p authz.Principal
	var err error
	user, password, basic := r.BasicAuth()
	switch {
	case r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && s.Listener.ClientSVIDAuth.Enabled:
		p, err = adminauth.SVID(r.TLS, s.Listener.ClientSVIDAuth.AcceptedTrustDomains)
	case basic && s.basicAllowed():
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		rl := s.Listener.RateLimit
		if !s.limits.allow("ip:"+ip, perMinute(rl.LoginPerIPPerMin, 10)) || !s.limits.allow("user:"+user, perMinute(rl.LoginPerUserPerMin, 5)) {
			return changerequests.Caller{}, errLoginLimited
		}
		p, err = s.LDAP.Authenticate(r.Context(), user, password)
	default:
		err = adminauth.ErrInvalidCredentials
	}
	if err != nil {
		return changerequests.Caller{}, err
	}
	return changerequests.Caller{Principal: p, Grants: s.Authz.For(p)}, nil
}

// apiRate is the caller's API rate: its bindings' rate_limit, else
// api_per_principal_rps (default 10).
func (s *Server) apiRate(c changerequests.Caller) rate {
	for _, g := range c.Grants {
		if g.RateLimit != nil && g.RateLimit.APIRPS > 0 {
			return rate{g.RateLimit.APIRPS, float64(max(g.RateLimit.Burst, 1))}
		}
	}
	rps := s.Listener.RateLimit.APIPerPrincipalRPS
	if rps <= 0 {
		rps = 10
	}
	return rate{rps, 2 * rps}
}

func perMinute(n, fallback int) rate {
	if n <= 0 {
		n = fallback
	}
	return rate{float64(n) / 60, float64(n)}
}

// rate is a token bucket's refill per second and size.
type rate struct{ perSecond, burst float64 }

type bucket struct {
	tokens float64
	at     time.Time
}

// limiter keeps a token bucket per key.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func (l *limiter) allow(key string, r rate) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.buckets == nil || len(l.buckets) > 100_000 {
		l.buckets = map[string]*bucket{} // shortcut: forgets every bucket when the map grows past 100k keys; prune by age if that ever matters
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: r.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = min(r.burst, b.tokens+now.Sub(b.at).Seconds()*r.perSecond)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// viewer: any role but break_glass alone (§7.2.2).
func viewer(c changerequests.Caller) bool {
	for _, g := range c.Grants {
		if g.Role != config.RoleBreakGlass {
			return true
		}
	}
	return false
}

// problem writes an RFC 9457 problem (§7.2.3 error model).
func problem(w http.ResponseWriter, code int, slug, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	if code == http.StatusServiceUnavailable && slug == "maintenance" {
		w.Header().Set("Retry-After", "60")
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ligo:problem:" + slug, "title": http.StatusText(code), "status": code, "detail": detail})
}

// fail writes err: a refusal with its status and slug, a missing row as
// not-found, anything else as a logged 500.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if e := (*changerequests.Error)(nil); errors.As(err, &e) {
		problem(w, e.Status, e.Slug, e.Detail)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	s.Logger.Error("request failed", "request_id", w.Header().Get("X-Request-Id"), "path", r.URL.Path, "error", err)
	problem(w, http.StatusInternalServerError, "internal", "internal error; see request "+w.Header().Get("X-Request-Id"))
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// decode reads a JSON body of at most 1 MiB, refusing unknown fields.
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "body: " + err.Error()}
	}
	return nil
}

// page reads pageSize (default 50, at most 200) and decodes pageToken
// into cursor (§7.2.3 keyset pagination).
func page(r *http.Request, cursor any) (int, error) {
	size := 50
	if v := r.URL.Query().Get("pageSize"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			return 0, &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "pageSize: 1 to 200"}
		}
		size = n
	}
	if t := r.URL.Query().Get("pageToken"); t != "" {
		raw, err := base64.RawURLEncoding.DecodeString(t)
		if err == nil {
			err = json.Unmarshal(raw, cursor)
		}
		if err != nil {
			return 0, &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "pageToken"}
		}
	}
	return size, nil
}

// token encodes the cursor of the next page, or nil.
func token(more bool, cursor any) *string {
	if !more {
		return nil
	}
	raw, _ := json.Marshal(cursor)
	t := base64.RawURLEncoding.EncodeToString(raw)
	return &t
}

// body reads a request body of at most 1 MiB for a service to decode.
func body(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err == nil && len(b) > 1<<20 {
		err = &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "body: larger than 1 MiB"}
	}
	return b, err
}

// filed answers a filed change: 202 with the request and, once applied,
// the resource (§7.2.3 responses).
func (s *Server) filed(w http.ResponseWriter, r *http.Request, cr *changerequests.Request, err error, resource func() (any, error)) {
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var res any
	if cr.Status == "APPLIED" && resource != nil {
		if res, err = resource(); err != nil {
			res = nil // retired or deleted by the change
		}
	}
	reply(w, http.StatusAccepted, map[string]any{"changeRequest": dto(cr, false), "resource": res})
}

func pathID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return id, &changerequests.Error{Status: 404, Slug: "not-found", Detail: fmt.Sprintf("change request %q", r.PathValue("id"))}
	}
	return id, nil
}
