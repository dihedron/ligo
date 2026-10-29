package pluginsdk

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRedactingHandler: secret-looking keys and SQL with IDENTIFIED BY never
// reach the log, in attributes, groups, WithAttrs or the message (§5.8 rule 6).
func TestRedactingHandler(t *testing.T) {
	var out strings.Builder
	log := slog.New(NewRedactingHandler(slog.NewTextHandler(&out, nil)))
	log.With("api_token", "tok-1").WithGroup("g").Info("ALTER USER x IDENTIFIED BY msg-pw",
		"password", "pw-1", "Client_Secret", "sec-1", "sql", `create user x identified by "pw-2"`,
		slog.Group("inner", "bootstrap_credential", "cred-1", "user", "admin"), "count", 3)
	got := out.String()
	for _, leak := range []string{"tok-1", "msg-pw", "pw-1", "sec-1", "pw-2", "cred-1"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q leaked: %s", leak, got)
		}
	}
	for _, keep := range []string{"admin", "count=3", "[REDACTED]"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q missing: %s", keep, got)
		}
	}
	if !NewRedactingHandler(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn})).Enabled(t.Context(), slog.LevelWarn) {
		t.Error("Enabled")
	}
}

// TestPluginError: the detail round-trips; the public message is capped and
// a malformed code is replaced (§5.8 rule 5, §5.9 PluginErrorDetail).
func TestPluginError(t *testing.T) {
	err := Error(codes.Unavailable, "BACKEND_DOWN", "the database does not answer", true)
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code %v", status.Code(err))
	}
	code, d := FromError(err)
	if code != codes.Unavailable || d.GetCode() != "BACKEND_DOWN" || d.GetPublicMessage() != "the database does not answer" || !d.GetRetryable() {
		t.Errorf("FromError = %v, %+v", code, d)
	}

	_, d = FromError(Error(codes.Internal, "not snake", strings.Repeat("é", 600), false))
	if d.GetCode() != "PLUGIN_ERROR" || len([]rune(d.GetPublicMessage())) != 512 {
		t.Errorf("malformed: %q, %d runes", d.GetCode(), len([]rune(d.GetPublicMessage())))
	}

	code, d = FromError(ErrOwnedByOtherBinding("role app_ro"))
	if code != codes.FailedPrecondition || d.GetCode() != "RESOURCE_OWNED_BY_OTHER_BINDING" || d.GetRetryable() {
		t.Errorf("owned: %v %+v", code, d)
	}

	// an error without a detail keeps only a generic code and no message
	code, d = FromError(status.Error(codes.Internal, "pq: password=secret"))
	if code != codes.Internal || d.GetCode() != "PLUGIN_ERROR" || d.GetPublicMessage() != "" {
		t.Errorf("no detail: %v %+v", code, d)
	}
	code, d = FromError(errors.New("plain"))
	if code != codes.Unknown || d.GetCode() != "PLUGIN_ERROR" {
		t.Errorf("plain: %v %+v", code, d)
	}
}

// TestGeneratePassword: [A-Za-z0-9], at least 32 characters (§5.8 rule 3).
func TestGeneratePassword(t *testing.T) {
	if _, err := GeneratePassword(31); err == nil {
		t.Error("31 characters accepted")
	}
	seen := map[string]bool{}
	for range 100 {
		p, err := GeneratePassword(32)
		if err != nil || len(p) != 32 || strings.Trim(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != "" {
			t.Fatalf("GeneratePassword = (%q, %v)", p, err)
		}
		seen[p] = true
	}
	if len(seen) != 100 {
		t.Error("repeated passwords")
	}
}
