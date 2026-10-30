package command

import (
	"github.com/dihedron/ligo/internal/command/serve"
	"github.com/dihedron/ligo/internal/command/version"
)

// Commands is the set of root command groups.
type Commands struct {
	// Version prints the program version information.
	Version version.Version `command:"version" alias:"v" description:"Print program version information."`
	// Serve runs the control-plane daemon.
	Serve serve.Serve `command:"serve" description:"Run the ligo control-plane daemon."`
}
