package adminclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The sentinels a caller decides on; errors.Is works on every error a call
// returns, through the *Problem.
var (
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("the resource changed: its revision is not the expected one")
	ErrState           = errors.New("the resource or the change request is not in a state that allows this")
	ErrInvalid         = errors.New("the request is invalid")
	ErrForbidden       = errors.New("forbidden")
	ErrUnauthenticated = errors.New("not authenticated")
	ErrUnavailable     = errors.New("the server is unavailable or limiting requests; retry later")
	ErrMaintenance     = errors.New("the server is in maintenance")
	ErrTooLarge        = errors.New("the response is larger than the client accepts")
	ErrRedirect        = errors.New("the server redirected the request; the client never follows a redirect")
)

// sentinels maps each problem slug the server sends to a sentinel
// (TestSlugsAreMapped fails on a slug that is in neither this map nor the
// test's list of slugs with none).
var sentinels = map[string]error{
	"not-found": ErrNotFound,

	"revision-conflict": ErrConflict,
	"resource-changed":  ErrConflict,

	"binding-busy":               ErrState,
	"invalid-transition":         ErrState,
	"resource-deprecated":        ErrState,
	"resource-in-use":            ErrState,
	"instance-in-use":            ErrState,
	"account-in-use":             ErrState,
	"account-exists":             ErrState,
	"binding-exists":             ErrState,
	"change-request-not-pending": ErrState,
	"change-request-pending":     ErrState,
	"dependency-pending":         ErrState,
	"break-glass-open":           ErrState,
	"break-glass-not-open":       ErrState,
	"break-glass-limit":          ErrState,
	"audit-export-recorded":      ErrState,
	"executor-alive":             ErrState,
	"executor-self":              ErrState,
	"resource-managed":           ErrState,
	"resource-held":              ErrState,

	"validation-failed":               ErrInvalid,
	"immutable-field":                 ErrInvalid,
	"jurisdiction-unresolvable":       ErrInvalid,
	"widening-not-allowed":            ErrInvalid,
	"sample-not-matched":              ErrInvalid,
	"source-not-exact":                ErrInvalid,
	"payload-mismatch":                ErrInvalid,
	"normalization-drift":             ErrInvalid,
	"side-required":                   ErrInvalid,
	"charter-changed":                 ErrInvalid,
	"interconnect-denied":             ErrInvalid,
	"flow-destination-not-allowed":    ErrInvalid,
	"namespace-mismatch":              ErrInvalid,
	"namespace-jurisdiction-mismatch": ErrInvalid,
	"account-jurisdiction-mismatch":   ErrInvalid,
	"account-not-registered":          ErrInvalid,

	"forbidden":                  ErrForbidden,
	"four-eyes-violation":        ErrForbidden,
	"distinct-approver-required": ErrForbidden,

	"unauthenticated": ErrUnauthenticated,

	"unavailable":            ErrUnavailable,
	"rate-limited":           ErrUnavailable,
	"dependency-unavailable": ErrUnavailable,

	"maintenance": ErrMaintenance,
}

const (
	problemPrefix = "urn:ligo:problem:"
	maxRetryAfter = time.Hour
)

// Problem is an RFC 9457 problem answered by the server. A response that is
// not a problem is a Problem with only its Status: its body never goes into
// an error, as it may come from a proxy and hold anything.
type Problem struct {
	Status     int
	Type       string
	Title      string
	Detail     string
	RetryAfter time.Duration // of a 503 or 429, when the server said so; at most an hour
}

// Slug is the problem's type without its urn:ligo:problem: prefix.
func (p *Problem) Slug() string { return strings.TrimPrefix(p.Type, problemPrefix) }

func (p *Problem) Error() string {
	switch {
	case p.Slug() == "" && p.Detail == "":
		return fmt.Sprintf("%d %s", p.Status, http.StatusText(p.Status))
	case p.Detail == "":
		return fmt.Sprintf("%d %s", p.Status, p.Slug())
	}
	return fmt.Sprintf("%d %s: %s", p.Status, p.Slug(), p.Detail)
}

// Unwrap is the sentinel of the problem's slug, if it has one; without one
// the status decides for the cases the client can tell apart.
func (p *Problem) Unwrap() error {
	if s, ok := sentinels[p.Slug()]; ok {
		return s
	}
	switch {
	case p.Slug() != "":
		return nil // an unknown slug: the caller reads it
	case p.Status == http.StatusUnauthorized:
		return ErrUnauthenticated
	case p.Status == http.StatusForbidden:
		return ErrForbidden
	case p.Status == http.StatusNotFound:
		return ErrNotFound
	case p.Status == http.StatusTooManyRequests || p.Status == http.StatusServiceUnavailable || p.Status == http.StatusBadGateway || p.Status == http.StatusGatewayTimeout:
		return ErrUnavailable
	}
	return nil
}

// problemOf reads the answer of a failed call.
func problemOf(resp *http.Response, body []byte) *Problem {
	p := &Problem{Status: resp.StatusCode}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil && (mt == "application/problem+json" || mt == "application/json") {
		var wire struct {
			Type   string `json:"type"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		// a problem has a type; any other JSON is not one
		if json.Unmarshal(body, &wire) == nil && strings.HasPrefix(wire.Type, problemPrefix) {
			p.Type, p.Title, p.Detail = wire.Type, wire.Title, wire.Detail
		}
	}
	if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests {
		p.RetryAfter = retryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	return p
}

// retryAfter reads a Retry-After as seconds or as an HTTP date, at most an
// hour; anything else is zero.
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return min(max(time.Duration(secs)*time.Second, 0), maxRetryAfter)
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(t.Sub(now), 0), maxRetryAfter)
	}
	return 0
}
