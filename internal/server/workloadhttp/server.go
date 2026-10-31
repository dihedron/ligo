// Package workloadhttp serves the read-only workload listener (§7.1):
// callers authenticate with an X.509-SVID or a JWT-SVID, within a rate
// limit per SPIFFE ID.
package workloadhttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/identity"
	"github.com/dihedron/ligo/internal/ratelimit"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// Bundles is the composite bundle source of the zones (§7.1).
type Bundles interface {
	x509bundle.Source
	jwtbundle.Source
}

// Server is the workload listener.
type Server struct {
	Listener config.WorkloadListener
	Bundles  Bundles
	Cache    Resolver
	Rules    *bindings.Rules // the platforms', secret stores' and ligo's flows
	Logger   *slog.Logger

	limits ratelimit.Limiter
	now    func() time.Time // the tests' clock; time.Now when nil
}

// TLSConfig is the listener's: TLS 1.3, the server certificate from cert
// and, with x509_svid, client X.509-SVIDs verified against the accepted
// trust domains' bundles at every handshake.
func (s *Server) TLSConfig(cert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	var bundles x509bundle.Source
	if s.Bundles != nil && slices.Contains(s.Listener.AuthModes, config.AuthX509SVID) {
		bundles = s.Bundles
	}
	return identity.ServerTLS(cert, bundles, s.Listener.AcceptedTrustDomains)
}

// Handler routes the workload API behind authentication and rate limiting.
func (s *Server) Handler() http.Handler { return s.middleware(s.routes()) }

type (
	callerKey    struct{}
	requestIDKey struct{}
)

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}

// Caller is the authenticated SPIFFE ID of a request.
func Caller(r *http.Request) spiffeid.ID {
	id, _ := r.Context().Value(callerKey{}).(spiffeid.ID)
	return id
}

var errUnauthenticated = errors.New("workloadhttp: invalid credentials")

// middleware tags the request, authenticates the caller and applies its
// rate limit; the access log never carries the Authorization header or
// the client certificate.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := uuid.NewV7().String()
		w.Header().Set("X-Request-Id", rid)
		start := time.Now()
		id, err := s.authenticate(r)
		switch {
		case err != nil:
			problem(w, http.StatusUnauthorized, "unauthenticated", "a valid X.509-SVID or JWT-SVID is required")
		case !s.limits.Allow(id.String(), ratelimit.Rate{PerSecond: s.Listener.RateLimit.PerSVIDRPS, Burst: float64(max(s.Listener.RateLimit.Burst, 1))}):
			w.Header().Set("Retry-After", "1")
			problem(w, http.StatusTooManyRequests, "rate-limited", "too many requests")
		default:
			rec := &status{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(rec, r.WithContext(context.WithValue(context.WithValue(r.Context(), callerKey{}, id), requestIDKey{}, rid)))
			s.Logger.Info("request", "request_id", rid, "caller", id.String(), "method", r.Method, "path", r.URL.Path,
				"status", rec.code, "duration", time.Since(start))
			return
		}
		s.Logger.Info("request refused", "request_id", rid, "caller", id.String(), "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	})
}

// authenticate evaluates auth_modes in order (§7.1): a verified client
// X.509-SVID, whose identity a bearer token, if any, must repeat; else a
// JWT-SVID.
func (s *Server) authenticate(r *http.Request) (spiffeid.ID, error) {
	token, bearer := bearerToken(r)
	if slices.Contains(s.Listener.AuthModes, config.AuthX509SVID) && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		id, err := identity.PeerID(r.TLS, s.Listener.AcceptedTrustDomains)
		if err != nil {
			return spiffeid.ID{}, errUnauthenticated
		}
		if bearer {
			if sub, err := s.jwt(token); err != nil || sub != id {
				return spiffeid.ID{}, errUnauthenticated
			}
		}
		return id, nil
	}
	if slices.Contains(s.Listener.AuthModes, config.AuthJWTSVID) && bearer {
		return s.jwt(token)
	}
	return spiffeid.ID{}, errUnauthenticated
}

// jwt validates a JWT-SVID: signature and expiry against the zones'
// bundles, expected_jwt_audience among its audiences, a required iat, a
// lifetime within max_token_ttl and no iat beyond clock_skew (EXT-12,
// AC-16).
func (s *Server) jwt(token string) (spiffeid.ID, error) {
	svid, err := jwtsvid.ParseAndValidate(token, s.Bundles, []string{s.Listener.ExpectedJWTAudience})
	if err != nil {
		return spiffeid.ID{}, errUnauthenticated
	}
	iatClaim, ok := svid.Claims["iat"].(float64)
	if !ok {
		return spiffeid.ID{}, errUnauthenticated
	}
	iat := time.Unix(int64(iatClaim), 0)
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	if svid.Expiry.Sub(iat) > s.Listener.MaxTokenTTL || iat.After(now().Add(s.Listener.ClockSkew)) ||
		!identity.Accepted(svid.ID, s.Listener.AcceptedTrustDomains) {
		return spiffeid.ID{}, errUnauthenticated
	}
	return svid.ID, nil
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// problem writes an RFC 9457 problem, as the admin API does.
func problem(w http.ResponseWriter, code int, slug, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ligo:problem:" + slug, "title": http.StatusText(code), "status": code, "detail": detail})
}

type status struct {
	http.ResponseWriter
	code int
}

func (s *status) WriteHeader(code int) { s.code = code; s.ResponseWriter.WriteHeader(code) }
