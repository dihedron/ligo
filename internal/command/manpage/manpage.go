// Package manpage writes the manual pages of the commands of ligo, one
// ligo-<command>(1) for each top-level command, from the option parser, so
// that the pages cannot drift from the command line.
package manpage

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	flags "github.com/jessevdk/go-flags"
)

const program = "ligo"

// esc escapes text for roff: backslashes and hyphens, and a leading control character.
func esc(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.NewReplacer(`\`, `\e`, "-", `\-`).Replace(s)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

// Pages returns the pages of the commands of p, by file name (ligo-source.1).
func Pages(p *flags.Parser) map[string]string {
	pages := map[string]string{}
	for _, c := range p.Commands() {
		if c.Hidden {
			continue
		}
		pages[program+"-"+c.Name+".1"] = page(p, c)
	}
	return pages
}

// common are the options of every command that calls the admin API: ligo(1)
// describes them once, so the pages of the commands leave them out.
var common = map[string]bool{"server": true, "ca-cert": true, "spiffe-socket": true, "server-id": true, "username": true, "password-file": true, "approval-ref": true, "automation-context": true}

func options(g *flags.Group) []*flags.Option {
	var opts []*flags.Option
	for _, o := range g.Options() {
		if !common[o.LongName] {
			opts = append(opts, o)
		}
	}
	for _, sub := range g.Groups() {
		opts = append(opts, options(sub)...)
	}
	sort.SliceStable(opts, func(i, j int) bool { return opts[i].LongName < opts[j].LongName })
	return opts
}

func optionLine(o *flags.Option) string {
	var parts []string
	if o.ShortName != 0 {
		parts = append(parts, `\fB\-`+string(o.ShortName)+`\fR`)
	}
	long := `\fB\-\-` + strings.ReplaceAll(o.LongName, "-", `\-`) + `\fR`
	if o.Field().Type.Kind() != reflect.Bool { // not a bool: it takes a value
		name := o.ValueName
		if name == "" {
			name = strings.ToUpper(o.LongName)
		}
		long += `=\fI` + esc(name) + `\fR`
	}
	parts = append(parts, long)
	return strings.Join(parts, ", ")
}

func optionBody(o *flags.Option) string {
	text := esc(o.Description)
	if len(o.Choices) > 0 {
		text += " One of: " + esc(strings.Join(o.Choices, ", ")) + "."
	}
	if len(o.Default) > 0 {
		text += " The default is " + esc(strings.Join(o.Default, ", ")) + "."
	}
	if o.EnvDefaultKey != "" {
		text += " Environment: " + esc(o.EnvDefaultKey) + "."
	}
	return text
}

func usage(c *flags.Command) string {
	var b strings.Builder
	for _, a := range c.Args() {
		name := strings.ToUpper(a.Name)
		if a.Required > 0 {
			b.WriteString(` \fI` + esc(name) + `\fR`)
		} else {
			b.WriteString(` [\fI` + esc(name) + `\fR]`)
		}
	}
	return b.String()
}

// walk calls f for the command and every subcommand below it, with the path of names.
func walk(c *flags.Command, path []string, f func(*flags.Command, []string)) {
	f(c, path)
	subs := append([]*flags.Command(nil), c.Commands()...)
	sort.SliceStable(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
	for _, s := range subs {
		if !s.Hidden {
			walk(s, append(append([]string(nil), path...), s.Name), f)
		}
	}
}

func page(p *flags.Parser, top *flags.Command) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	title := strings.ToUpper(program + "-" + top.Name)
	w(".\\\" Generated from the command line of ligo; do not edit.\n")
	w(".TH %q \"1\" \"\" %q \"User Commands\"\n", strings.ReplaceAll(title, "-", `\-`), program)
	w(".SH NAME\n%s \\- %s\n", esc(program+"-"+top.Name), esc(top.ShortDescription))
	w(".SH SYNOPSIS\n")
	if len(top.Commands()) == 0 {
		w("\\fB%s\\fR [\\fIGLOBAL OPTIONS\\fR] \\fB%s\\fR [\\fIOPTIONS\\fR]%s\n", program, esc(top.Name), usage(top))
	} else {
		w("\\fB%s\\fR [\\fIGLOBAL OPTIONS\\fR] \\fB%s\\fR \\fICOMMAND\\fR [\\fIOPTIONS\\fR] [\\fIARGUMENTS\\fR]\n", program, esc(top.Name))
	}
	w(".SH DESCRIPTION\n%s\n", esc(top.ShortDescription))
	if len(top.Aliases) > 0 {
		w(".PP\nAlias: %s.\n", esc(strings.Join(top.Aliases, ", ")))
	}
	if opts := options(top.Group); len(opts) > 0 {
		w(".SH OPTIONS\n")
		for _, o := range opts {
			w(".TP\n%s\n%s\n", optionLine(o), optionBody(o))
		}
	}
	if len(top.Commands()) > 0 {
		w(".SH COMMANDS\n")
		walk(top, nil, func(c *flags.Command, path []string) {
			if len(path) == 0 {
				return
			}
			names := []string{`\fB` + esc(strings.Join(path, " ")) + `\fR`}
			for _, a := range c.Aliases {
				alias := append(append([]string(nil), path[:len(path)-1]...), a)
				names = append(names, `\fB`+esc(strings.Join(alias, " "))+`\fR`)
			}
			w(".TP\n%s%s\n%s\n", strings.Join(names, ", "), usage(c), esc(c.ShortDescription))
			for _, o := range options(c.Group) {
				w(".RS\n.TP\n%s\n%s\n.RE\n", optionLine(o), optionBody(o))
			}
		})
	}
	w(".SH CONNECTION\nThe commands that call the admin API take the options \\fB\\-\\-server\\fR, \\fB\\-\\-ca\\-cert\\fR, \\fB\\-\\-spiffe\\-socket\\fR, \\fB\\-\\-server\\-id\\fR, \\fB\\-\\-username\\fR and \\fB\\-\\-password\\-file\\fR, and, when they write, \\fB\\-\\-approval\\-ref\\fR and \\fB\\-\\-automation\\-context\\fR; \\fB%s\\fR(1) describes them.\n", program)
	w(".SH SEE ALSO\n\\fB%s\\fR(1)\n", program)
	_ = p
	return b.String()
}
