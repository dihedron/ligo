package pluginmgr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Owner is the owner every plugin directory and binary must have.
type Owner struct{ UID, GID uint32 }

// Root is the owner §5.3 rule 3 requires.
var Root = Owner{}

// Binary is a plugin binary opened, checked and hashed through one
// descriptor, and executed through that descriptor, so that the file that
// runs is the file that was checked (§5.3 rules 3-4).
type Binary struct {
	file     *os.File
	checksum []byte
}

// OpenBinary opens dir/name and checks, before every spawn, that the
// directory and the binary are not symlinks, are owned by owner and are not
// writable by group or others, that the binary is a regular file, and that
// its SHA-256 is want.
func OpenBinary(dir, name string, want []byte, owner Owner) (*Binary, error) {
	if name == "" || strings.ContainsRune(name, '/') {
		return nil, fmt.Errorf("plugin binary %q: must be a file name in the plugins directory", name)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("plugins directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("plugins directory %s: a symlink or not a directory", dir)
	}
	if err := checkOwnership(dir, info, owner); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	// O_NOFOLLOW refuses a symlink in the same step that opens the file
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("plugin binary %s: a symlink", path)
	}
	if err != nil {
		return nil, fmt.Errorf("plugin binary %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	b, err := check(f, owner, want)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return b, nil
}

func check(f *os.File, owner Owner, want []byte) (*Binary, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("plugin binary %s: not a regular file", f.Name())
	}
	if err := checkOwnership(f.Name(), info, owner); err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("plugin binary %s: %w", f.Name(), err)
	}
	if sum := h.Sum(nil); !bytes.Equal(sum, want) {
		return nil, fmt.Errorf("plugin binary %s: checksum %s, want %s", f.Name(), hex.EncodeToString(sum), hex.EncodeToString(want))
	}
	return &Binary{file: f, checksum: want}, nil
}

func checkOwnership(path string, info fs.FileInfo, owner Owner) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: no ownership information", path)
	}
	if st.Uid != owner.UID || st.Gid != owner.GID {
		return fmt.Errorf("%s: owned by %d:%d, want %d:%d", path, st.Uid, st.Gid, owner.UID, owner.GID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: writable by group or others (%v)", path, info.Mode().Perm())
	}
	return nil
}

// Command runs the checked file through its descriptor. The descriptor is
// close-on-exec: Linux opens /proc/self/fd/N before it closes it, which
// works for executables (not for scripts, which plugins are not).
func (b *Binary) Command() *exec.Cmd {
	return exec.Command(fmt.Sprintf("/proc/self/fd/%d", b.file.Fd())) //nolint:gosec // the path is our own checked descriptor
}

// Checksum is the binary's verified SHA-256, for go-plugin's SecureConfig,
// which hashes it again through the same descriptor.
func (b *Binary) Checksum() []byte { return b.checksum }

// Close releases the descriptor, once the plugin process has started.
func (b *Binary) Close() error { return b.file.Close() }
