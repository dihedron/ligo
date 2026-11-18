package completion

import (
	"fmt"
	"os"

	flags "github.com/jessevdk/go-flags"
)

// Completion is the command that prints the completion script of a shell.
type Completion struct {
	Args struct {
		Shell string `positional-arg-name:"shell" required:"yes" description:"bash, zsh, fish or powershell"`
	} `positional-args:"yes"`
	parser *flags.Parser
}

// SetParser receives the parser of the whole command line, whose tree the script describes.
func (c *Completion) SetParser(p *flags.Parser) { c.parser = p }

// Execute writes the script of the shell to the standard output.
func (c *Completion) Execute([]string) error {
	if c.parser == nil {
		return fmt.Errorf("no command tree to describe")
	}
	return Write(os.Stdout, c.Args.Shell, c.parser)
}
