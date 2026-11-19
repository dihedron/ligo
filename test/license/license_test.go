// Package license checks that the MIT-licensed client libraries depend on nothing of the
// AGPL-licensed server (.specs/ligo-backlog.md §26).
package license

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/dihedron/ligo"

// mit are the directories under the MIT license, each with its own LICENSE file.
var mit = []string{"pkg/client", "pkg/adminclient", "internal/adminraw", "api/proto/workload", "api/gen/workload", "api/openapi", "sdk/python"}

func TestEachMITDirectoryHasItsLicense(t *testing.T) {
	for _, d := range mit {
		b, err := os.ReadFile(filepath.Join("..", "..", d, "LICENSE"))
		if err != nil || !strings.HasPrefix(string(b), "MIT License") {
			t.Errorf("%s: no MIT LICENSE file (%v)", d, err)
		}
	}
}

// TestMITPackagesImportNoServerCode: what the client libraries import from this module is MIT too.
func TestMITPackagesImportNoServerCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", module+"/pkg/client", module+"/pkg/adminclient").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		rel, ok := strings.CutPrefix(pkg, module+"/")
		if !ok {
			continue
		}
		allowed := false
		for _, d := range mit {
			if rel == d || strings.HasPrefix(rel, d+"/") {
				allowed = true
			}
		}
		if !allowed {
			t.Errorf("an MIT package imports %s, which is under the AGPL", pkg)
		}
	}
}
