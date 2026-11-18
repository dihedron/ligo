// Command genman writes the ligo-<command>(1) manual pages of the ligo command
// line into a directory: go run ./internal/tools/genman DIR. The release runs
// it; the pages are built from the option parser and are not committed.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dihedron/ligo/cmd/ligo/command"
	"github.com/dihedron/ligo/internal/command/manpage"
	flags "github.com/jessevdk/go-flags"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genman DIRECTORY")
		os.Exit(2)
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // a build tool: the directory is the caller's argument
		fmt.Fprintln(os.Stderr, "genman:", err)
		os.Exit(1)
	}
	for name, page := range manpage.Pages(flags.NewParser(&command.Commands{}, flags.Default)) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(page), 0o644); err != nil { //nolint:gosec // a manual page is world-readable
			fmt.Fprintln(os.Stderr, "genman:", err)
			os.Exit(1)
		}
	}
}
