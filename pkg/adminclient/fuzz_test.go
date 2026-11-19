// SPDX-License-Identifier: MIT

package adminclient

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
)

// FuzzProblemOf: whatever a server sends with an error, the client reads it
// without panicking, a body that is not a problem leaves no text in the
// error (T-A2, T-A3), and the sentinel lookup never fails.
func FuzzProblemOf(f *testing.F) {
	for _, seed := range []string{
		`{"type":"urn:ligo:problem:not-found","title":"Not Found","status":404,"detail":"source \"s\""}`,
		`{"type":"urn:ligo:problem:maintenance","status":503}`,
		`{"password":"hunter2"}`, `<html>bad gateway</html>`, ``, `null`, `[]`, `{"type":1}`, `{"type":"urn:ligo:problem:","detail":"x"}`,
	} {
		f.Add([]byte(seed), "application/problem+json", 409, "60")
		f.Add([]byte(seed), "text/html", 502, "")
	}
	f.Fuzz(func(t *testing.T, body []byte, contentType string, status int, retry string) {
		resp := &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}, "Retry-After": {retry}}}
		p := problemOf(resp, body)
		if p.Status != status {
			t.Fatalf("status %d became %d", status, p.Status)
		}
		if p.Type == "" && (p.Detail != "" || p.Title != "") {
			t.Fatalf("a body that is not a problem left text: %+v", p)
		}
		if p.Type != "" && !strings.HasPrefix(p.Type, problemPrefix) {
			t.Fatalf("a type outside the namespace was kept: %q", p.Type)
		}
		if p.RetryAfter < 0 || p.RetryAfter > time.Hour {
			t.Fatalf("Retry-After %s", p.RetryAfter)
		}
		_ = p.Error()
		_ = p.Unwrap()
		_ = p.Slug()
	})
}

// FuzzRetryAfter: any header value is zero or within an hour.
func FuzzRetryAfter(f *testing.F) {
	for _, s := range []string{"", "0", "60", "-1", "99999999999999999999", "Wed, 21 Oct 2026 07:28:00 GMT", "soon", "1e3", " 5"} {
		f.Add(s)
	}
	now := time.Date(2026, 10, 21, 7, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, v string) {
		if d := retryAfter(v, now); d < 0 || d > time.Hour {
			t.Fatalf("%q gave %s", v, d)
		}
	})
}

// FuzzPageToken: a token is opaque, and reaches the server exactly as it came,
// whatever bytes it holds.
func FuzzPageToken(f *testing.F) {
	for _, s := range []string{"", "p2", "a b&c=d", "é€𝄞", "%00", "a+b", "../..", "x\ny"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		req, err := gen.NewListAccountsRequest("https://ligo.lab:9443", &gen.ListAccountsParams{PageToken: opt[string](token)})
		if err != nil {
			t.Fatal(err)
		}
		q, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			t.Fatalf("the query %q does not parse: %v", req.URL.RawQuery, err)
		}
		switch got, ok := q["pageToken"]; {
		case token == "" && ok:
			t.Fatalf("an empty token was sent: %q", req.URL.RawQuery)
		case token != "" && (len(got) != 1 || got[0] != token):
			t.Fatalf("token %q arrived as %q", token, got)
		}
		if req.URL.Host != "ligo.lab:9443" || req.URL.Path != "/v1/admin/accounts" {
			t.Fatalf("a token moved the request to %s", req.URL)
		}
	})
}
