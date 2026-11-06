package schemas

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadable keeps every schema file of the repository indented: they are
// read by people and included in the manuals.
func TestReadable(t *testing.T) {
	root := filepath.Join("..", "..")
	found := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != root && strings.HasPrefix(d.Name(), ".") { // .git, the lab's state
			return filepath.SkipDir
		}
		if d.IsDir() || filepath.Ext(path) != ".json" || !strings.Contains(filepath.ToSlash(path), "/schemas/") {
			return nil
		}
		found++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var want bytes.Buffer
		if err := json.Indent(&want, bytes.TrimSpace(data), "", "  "); err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		want.WriteByte('\n')
		if !bytes.Equal(data, want.Bytes()) {
			t.Errorf("%s is not indented with two spaces", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 11 {
		t.Errorf("found %d schema files, want at least 11", found)
	}
}
