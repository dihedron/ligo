package main

import (
	"os"

	"github.com/dihedron/ligo/cmd/ligo/command"
	"github.com/dihedron/ligo/internal/client"
	"github.com/jessevdk/go-flags"
)

func main() {
	os.Exit(run())
}

// run parses the command line and runs the command; it returns the exit
// code so that the deferred cleanup runs before the process exits.
func run() int {
	defer cleanup()

	options := command.Commands{}
	parser := flags.NewParser(&options, flags.Default)
	// the admin commands read the global options (output format, log level)
	parser.CommandHandler = func(cmd flags.Commander, args []string) error {
		if cmd == nil {
			return nil
		}
		if g, ok := cmd.(interface{ SetGlobals(*client.Globals) }); ok {
			g.SetGlobals(&options.Globals)
		}
		return cmd.Execute(args)
	}
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			return 0
		}
		return 1
	}
	return 0
}
