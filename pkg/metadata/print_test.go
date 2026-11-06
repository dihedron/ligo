package metadata

import (
	"bytes"
	"strings"
	"testing"
)

// PrintFull writes to its writer, not to the process's standard output.
func TestPrintFullUsesWriter(t *testing.T) {
	var out bytes.Buffer
	PrintFull(&out)
	if !strings.Contains(out.String(), "Version") {
		t.Fatalf("nothing written: %q", out.String())
	}
	if n := strings.Count(out.String(), "Git Time"); n != 1 {
		t.Errorf("Git Time printed %d times", n)
	}
}
