package pluginmgr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
)

// me is the owner of the files the tests create; production requires root.
func me() Owner { return Owner{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} }

// pluginDir is a plugins.directory holding a copy of the test plugin.
func pluginDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "plugins")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	install(t, testPlugin, filepath.Join(dir, "testplugin"))
	return dir
}

func install(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(to, 0o755); err != nil { // whatever the umask
		t.Fatal(err)
	}
}

// TestOpenBinary: a checked binary runs through its descriptor (§5.3 rules
// 3-4).
func TestOpenBinary(t *testing.T) {
	dir := pluginDir(t)
	b, err := OpenBinary(dir, "testplugin", checksum(t, testPlugin), me())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	cmd := b.Command()
	if !strings.HasPrefix(cmd.Path, "/proc/self/fd/") {
		t.Errorf("command path %s", cmd.Path)
	}
	c, err := Start(cmd, pluginv2.PluginKind_PLUGIN_KIND_TARGET_PROVIDER, b.Checksum(), quiet(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Kill()
	if d, err := c.Control.Describe(context.Background(), &pluginv2.DescribeRequest{}); err != nil || d.GetPluginType() != "test.v1" {
		t.Errorf("Describe = (%v, %v)", d, err)
	}
}

// TestOpenBinarySwapped: a binary replaced after the check is not what
// runs: the descriptor holds the checked file.
func TestOpenBinarySwapped(t *testing.T) {
	dir := pluginDir(t)
	b, err := OpenBinary(dir, "testplugin", checksum(t, testPlugin), me())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	impostor := filepath.Join(dir, "impostor")
	if err := os.WriteFile(impostor, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(impostor, filepath.Join(dir, "testplugin")); err != nil {
		t.Fatal(err)
	}
	c, err := Start(b.Command(), pluginv2.PluginKind_PLUGIN_KIND_TARGET_PROVIDER, b.Checksum(), quiet(), nil)
	if err != nil {
		t.Fatalf("the checked binary did not run: %v", err)
	}
	c.Kill()
}

// TestOpenBinaryRefusals: every violation of §5.3 rules 3-4 refuses the
// spawn.
func TestOpenBinaryRefusals(t *testing.T) {
	sum := checksum(t, testPlugin)
	for name, tc := range map[string]struct {
		setup func(t *testing.T, dir string) (string, string) // directory and name to open
		owner Owner
		sum   []byte
		want  string
	}{
		"group-writable directory": {setup: func(t *testing.T, dir string) (string, string) {
			chmod(t, dir, 0o775)
			return dir, "testplugin"
		}, want: "writable"},
		"others-writable binary": {setup: func(t *testing.T, dir string) (string, string) {
			chmod(t, filepath.Join(dir, "testplugin"), 0o757)
			return dir, "testplugin"
		}, want: "writable"},
		"symlinked binary": {setup: func(t *testing.T, dir string) (string, string) {
			if err := os.Symlink(filepath.Join(dir, "testplugin"), filepath.Join(dir, "link")); err != nil {
				t.Fatal(err)
			}
			return dir, "link"
		}, want: "symlink"},
		"symlinked directory": {setup: func(t *testing.T, dir string) (string, string) {
			link := dir + "-link"
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			return link, "testplugin"
		}, want: "symlink"},
		"not a regular file": {setup: func(t *testing.T, dir string) (string, string) {
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			return dir, "sub"
		}, want: "regular file"},
		"missing": {setup: func(_ *testing.T, dir string) (string, string) { return dir, "nothing" }, want: "nothing"},
		"path in the name": {setup: func(_ *testing.T, dir string) (string, string) {
			return filepath.Dir(dir), "plugins/testplugin"
		}, want: "file name"},
		"foreign owner": {setup: func(_ *testing.T, dir string) (string, string) { return dir, "testplugin" },
			owner: Owner{UID: me().UID + 1, GID: me().GID}, want: "owned by"},
		"wrong checksum": {setup: func(_ *testing.T, dir string) (string, string) { return dir, "testplugin" },
			sum: make([]byte, 32), want: "checksum"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, file := tc.setup(t, pluginDir(t))
			owner, want := me(), sum
			if tc.owner != (Owner{}) {
				owner = tc.owner
			}
			if tc.sum != nil {
				want = tc.sum
			}
			b, err := OpenBinary(dir, file, want, owner)
			if err == nil {
				_ = b.Close()
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want %q", err, tc.want)
			}
		})
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
