package workflows

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dihedron/ligo/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestCall: retryable errors are retried with backoff up to the attempts,
// others fail at once; a PluginErrorDetail decides over the gRPC code, and
// only the code and public message are kept (§6.1 rules 3 to 5).
func TestCall(t *testing.T) {
	e := &Engine{Backoff: Backoff{Attempts: 3, Initial: time.Millisecond, Max: 2 * time.Millisecond}}
	for name, tc := range map[string]struct {
		err   error
		calls int
		code  string
	}{
		"retryable code":            {status.Error(codes.Unavailable, "down"), 3, "Unavailable"},
		"terminal code":             {status.Error(codes.PermissionDenied, "no"), 1, "PermissionDenied"},
		"detail retryable":          {pluginsdk.Error(codes.FailedPrecondition, "LOCKED", "busy", true), 3, "LOCKED"},
		"detail overrides the code": {pluginsdk.Error(codes.Unavailable, "GONE", "gone for good", false), 1, "GONE"},
	} {
		calls := 0
		err := e.call(context.Background(), func(context.Context) error { calls++; return tc.err })
		var se *StepError
		if calls != tc.calls || !errors.As(err, &se) || se.Code != tc.code {
			t.Errorf("%s: %d calls, %v", name, calls, err)
		}
	}
	calls := 0
	err := e.call(context.Background(), func(context.Context) error {
		if calls++; calls < 2 {
			return status.Error(codes.Unavailable, "blip")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Errorf("recovered call: %d calls, %v", calls, err)
	}
	if se := sanitize(status.Error(codes.Internal, "SELECT password FROM users")); se.Message != "the plugin call failed" {
		t.Errorf("an internal message leaked: %q", se.Message)
	}
}
