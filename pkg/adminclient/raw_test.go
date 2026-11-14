package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDo: the raw call has what every call has: the credentials, JSON both
// ways, the query, problems as *Problem, and the checks of a path.
func TestDo(t *testing.T) {
	var user, ctype, method, rawQuery string
	var in map[string]any
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ = r.BasicAuth()
		ctype, method, rawQuery = r.Header.Get("Content-Type"), r.Method, r.URL.RawQuery
		in = nil
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/v1/admin/echo":
			_, _ = w.Write([]byte(`{"ok":true,"items":[1,2]}`))
		case "/v1/admin/gone":
			problem(w, 404, "not-found", "no such thing")
		}
	}))
	ctx := context.Background()
	var out any
	if err := c.Do(ctx, "PUT", "/v1/admin/echo", url.Values{"q": {"a b"}, "n": {"1"}}, map[string]any{"enabled": true}, &out); err != nil {
		t.Fatal(err)
	}
	if user != "ada" || method != "PUT" || ctype != "application/json" || rawQuery != "n=1&q=a+b" || in["enabled"] != true || out.(map[string]any)["ok"] != true {
		t.Errorf("user %q, %s, %q, %q, body %v, answer %v", user, method, ctype, rawQuery, in, out)
	}
	if err := c.Do(ctx, "GET", "/v1/admin/echo", nil, nil, nil); err != nil || ctype != "" {
		t.Errorf("no body, no answer wanted: %v, content type %q", err, ctype)
	}
	err := c.Do(ctx, "GET", "/v1/admin/gone", nil, nil, nil)
	var p *Problem
	if !errors.Is(err, ErrNotFound) || !errors.As(err, &p) || p.Error() != "404 not-found: no such thing" {
		t.Errorf("a problem: %v", err)
	}
	for _, bad := range []string{"v1/admin/x", "//evil.example/x", "/v1/admin/x?a=b", "/v1/admin/x#f", ""} {
		if err := c.Do(ctx, "GET", bad, nil, nil, nil); err == nil {
			t.Errorf("path %q was accepted", bad)
		}
	}
	if err := c.Do(ctx, "POST", "/v1/admin/echo", nil, make(chan int), nil); err == nil {
		t.Error("a body that is not JSON was accepted")
	}
}

// TestDoStreams: an answer copied to a writer has no size limit, is not
// retried, and a problem is still a problem.
func TestDoStreams(t *testing.T) {
	var calls atomic.Int32
	chunk := strings.Repeat("x", 1<<20)
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/v1/admin/down" {
			problem(w, 503, "unavailable", "later")
			return
		}
		for range 10 {
			_, _ = w.Write([]byte(chunk))
		}
	}))
	var buf bytes.Buffer
	if err := c.Do(context.Background(), "GET", "/v1/admin/export", nil, nil, &buf); err != nil || buf.Len() != 10<<20 {
		t.Errorf("%d bytes, %v", buf.Len(), err)
	}
	// the same answer decoded is cut at the limit
	var v any
	if err := c.Do(context.Background(), "GET", "/v1/admin/export", nil, nil, &v); !errors.Is(err, ErrTooLarge) {
		t.Errorf("10 MiB decoded: %v", err)
	}
	calls.Store(0)
	buf.Reset()
	err := c.Do(context.Background(), "GET", "/v1/admin/down", nil, nil, &buf)
	if !errors.Is(err, ErrUnavailable) || calls.Load() != 1 || buf.Len() != 0 {
		t.Errorf("a failing stream: %v after %d calls, %d bytes written", err, calls.Load(), buf.Len())
	}
	// failing to write stops the copy
	if err := c.Do(context.Background(), "GET", "/v1/admin/export", nil, nil, failingWriter{}); err == nil {
		t.Error("a writer error was swallowed")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
