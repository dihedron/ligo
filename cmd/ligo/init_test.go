package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// built returns a ligo binary: init() reads variables named after the binary,
// and DotEnvVarName is stamped at build time.
func built(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ligo")
	cmd := exec.Command("go", "build", "-ldflags", "-X github.com/dihedron/ligo/pkg/metadata.DotEnvVarName=LIGO_DOTENV", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func runLigo(t *testing.T, bin string, env ...string) (code int, stderr string) {
	t.Helper()
	cmd := exec.Command(bin, "version")
	cmd.Env = append([]string{"HOME=" + t.TempDir()}, env...)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, errb.String()
}

// TestLogLevels: the parser and init() accept the same values.
func TestLogLevels(t *testing.T) {
	bin := built(t)
	for _, v := range []string{"debug", "info", "warn", "error", "off"} {
		if code, stderr := runLigo(t, bin, "LIGO_LOG_LEVEL="+v); code != 0 {
			t.Errorf("%s: exit %d: %s", v, code, stderr)
		}
	}
	for _, v := range []string{"none", "warning", "dbg", "bogus"} {
		if code, _ := runLigo(t, bin, "LIGO_LOG_LEVEL="+v); code == 0 {
			t.Errorf("%s: accepted", v)
		}
	}
}

// TestDotEnvLogging: its lines follow the configured level.
func TestDotEnvLogging(t *testing.T) {
	bin := built(t)
	good := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(good, []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const loaded, failed = "successfully loaded", "error loading"
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		name, file, level, want string
		silent                  bool
	}{
		{name: "off, good", file: good, level: "off", silent: true},
		{name: "off, missing", file: missing, level: "off", silent: true},
		{name: "unset, good", file: good, silent: true},
		{name: "error, good", file: good, level: "error", silent: true},
		{name: "info, good", file: good, level: "info", want: loaded},
		{name: "error, missing", file: missing, level: "error", want: failed},
		{name: "unset, missing", file: missing, want: failed}, // a failure is never lost by default
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{"LIGO_DOTENV=" + tc.file}
			if tc.level != "" {
				env = append(env, "LIGO_LOG_LEVEL="+tc.level)
			}
			code, stderr := runLigo(t, bin, env...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			if tc.silent && stderr != "" {
				t.Errorf("stderr: %s", stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr %q does not contain %q", stderr, tc.want)
			}
		})
	}
}
