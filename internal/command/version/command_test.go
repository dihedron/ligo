package version

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRelevantEnv(t *testing.T) {
	tests := []struct {
		env, want string
		ok        bool
	}{
		{"LIGO_DOTENV=/etc/ligo/.env", "LIGO_DOTENV=/etc/ligo/.env", true},
		{"LIGO_LOG_LEVEL=debug", "LIGO_LOG_LEVEL=debug", true},
		{"LIGO_TRUST_PASSWORD=hunter2", "LIGO_TRUST_PASSWORD=********", true},
		{"LIGO_CLIENT_SECRET=s3cr3t", "LIGO_CLIENT_SECRET=********", true},
		{"OS_AUTH_URL=https://keystone:5000/v3", "", false},
		{"HOME=/root", "", false},
		{"MIDPOINT_PASSWORD=x", "", false},
	}
	for _, tt := range tests {
		got, ok := relevantEnv(tt.env)
		if got != tt.want || ok != tt.ok {
			t.Errorf("relevantEnv(%q) = %q, %v; want %q, %v", tt.env, got, ok, tt.want, tt.ok)
		}
	}
}

// TestExecute runs the command in both modes and checks that the verbose
// listing masks secrets.
func TestExecute(t *testing.T) {
	dotenv := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(dotenv, []byte("LIGO_TEST_SETTING=on\nLIGO_TEST_PASSWORD=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("LIGO_TEST_SETTING"); _ = os.Unsetenv("LIGO_TEST_PASSWORD") })
	missing := filepath.Join(t.TempDir(), "missing")
	for _, cmd := range []Version{{}, {Verbose: true}, {Verbose: true, DotEnv: &dotenv}, {Verbose: true, DotEnv: &missing}} {
		out := capture(t, func() error { return cmd.Execute(nil) })
		if cmd.DotEnv == &dotenv && (!strings.Contains(out, "LIGO_TEST_SETTING=on") || !strings.Contains(out, "LIGO_TEST_PASSWORD=********") || strings.Contains(out, "hunter2")) {
			t.Errorf("verbose output:\n%s", out)
		}
	}
}

// capture returns what f writes to standard output.
func capture(t *testing.T, f func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	err = f()
	os.Stdout = stdout
	_ = w.Close()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	return string(out)
}
