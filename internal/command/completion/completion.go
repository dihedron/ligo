// Package completion prints the shell completion scripts of ligo: bash, zsh,
// fish and PowerShell. The scripts are static, built from the whole command
// tree of the option parser: pressing TAB never runs ligo, so it never reaches
// a server or reads a credential.
package completion

import (
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	flags "github.com/jessevdk/go-flags"
)

const program = "ligo"

// Shells are the shells a script can be written for.
var Shells = []string{"bash", "fish", "powershell", "zsh"}

// fileOptions are the options whose value is a file name.
var fileOptions = map[string]bool{"config": true, "dotenv": true, "password-file": true, "ca-cert": true, "spiffe-socket": true, "file": true, "template": true}

// option is what a completion needs to know about an option.
type option struct {
	short, long, description string // short and long are without dashes
	choices                  []string
	takesValue, file         bool
}

func (o option) spellings() []string {
	s := []string{"--" + o.long}
	if o.short != "" {
		s = append(s, "-"+o.short)
	}
	return s
}

// node is a command of the tree.
type node struct {
	name        string
	aliases     []string
	description string
	path        string   // names joined by "/", empty for the root
	options     []option // its own
	subs        []*node
}

func (n *node) words() []string { return append([]string{n.name}, n.aliases...) }

// optionsOf reads the options of a command, those of its option groups included.
func optionsOf(g *flags.Group) []option {
	var out []option
	for _, o := range g.Options() {
		x := option{long: o.LongName, description: o.Description, choices: o.Choices, takesValue: o.Field().Type.Kind() != reflect.Bool}
		if o.ShortName != 0 {
			x.short = string(o.ShortName)
		}
		x.file = o.ValueName == "FILE" || fileOptions[o.LongName]
		if x.long != "" {
			out = append(out, x)
		}
	}
	for _, c := range g.Groups() {
		out = append(out, optionsOf(c)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].long < out[j].long })
	return out
}

func build(c *flags.Command, path string) *node {
	n := &node{name: c.Name, aliases: c.Aliases, description: c.ShortDescription, path: path, options: optionsOf(c.Group)}
	cmds := c.Commands()
	sort.SliceStable(cmds, func(i, j int) bool { return cmds[i].Name < cmds[j].Name })
	for _, s := range cmds {
		if s.Hidden {
			continue
		}
		p := s.Name
		if path != "" {
			p = path + "/" + s.Name
		}
		n.subs = append(n.subs, build(s, p))
	}
	return n
}

// tree reads the command tree of the parser; the root carries the help flag.
func tree(p *flags.Parser) *node {
	root := build(p.Command, "")
	root.name = program
	hasHelp := false
	for _, o := range root.options {
		hasHelp = hasHelp || o.long == "help"
	}
	if !hasHelp { // the parser adds its help group lazily
		root.options = append(root.options, option{short: "h", long: "help", description: "Show this help message"})
	}
	return root
}

// effective is the options a command accepts: its own and those of its ancestors.
func effective(root *node, n *node) []option {
	out := append([]option(nil), root.options...)
	if n == root {
		return out
	}
	cur := root
	for _, part := range strings.Split(n.path, "/") {
		for _, s := range cur.subs {
			if s.name == part {
				cur = s
				out = append(out, s.options...)
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].long < out[j].long })
	return out
}

func (n *node) each(f func(*node)) {
	f(n)
	for _, s := range n.subs {
		s.each(f)
	}
}

// valueOptions merges the options that take a value by spelling; choices are united.
func valueOptions(root *node) (spellings []string, by map[string]option) {
	by = map[string]option{}
	root.each(func(n *node) {
		for _, o := range n.options {
			if !o.takesValue {
				continue
			}
			for _, s := range o.spellings() {
				if prev, ok := by[s]; ok {
					o.choices = union(prev.choices, o.choices)
					o.file = o.file || prev.file
				}
				by[s] = o
			}
		}
	})
	for s := range by {
		spellings = append(spellings, s)
	}
	sort.Strings(spellings)
	return spellings, by
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Write writes the completion script of shell for the commands of p.
func Write(w io.Writer, shell string, p *flags.Parser) error {
	gen := map[string]func(io.Writer, *node){"bash": bash, "zsh": zsh, "fish": fish, "powershell": powershell}[shell]
	if gen == nil {
		return fmt.Errorf("unknown shell %q: one of %s", shell, strings.Join(Shells, ", "))
	}
	gen(w, tree(p))
	return nil
}

func put(w io.Writer, s string) { _, _ = io.WriteString(w, s) }

func putf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

// singleLine makes a description fit on one line.
func singleLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// quoteSh quotes s as one word for sh and bash: '...' with ' as '\”.
func quoteSh(s string) string { return "'" + strings.ReplaceAll(singleLine(s), "'", `'\''`) + "'" }

// zshText escapes s for a zsh _arguments or _describe description.
func zshText(s string) string {
	return strings.NewReplacer(`\`, `\\`, "[", `\[`, "]", `\]`, ":", `\:`).Replace(singleLine(s))
}

// quoteZsh quotes s as a zsh description word.
func quoteZsh(s string) string { return quoteSh(zshText(s)) }

// quoteFish quotes s for fish: single quotes, where only \ and ' are special.
func quoteFish(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, "'", `\'`).Replace(singleLine(s)) + "'"
}

// quotePS quotes s for PowerShell: single quotes, with ' doubled.
func quotePS(s string) string { return "'" + strings.ReplaceAll(singleLine(s), "'", "''") + "'" }

func joinWords(ws []string) string { return strings.Join(ws, " ") }

func optionWords(opts []option) []string {
	var out []string
	for _, o := range opts {
		out = append(out, o.spellings()...)
	}
	return out
}

func subWords(n *node) []string {
	var out []string
	for _, s := range n.subs {
		out = append(out, s.words()...)
	}
	return out
}

// walkTable writes the case labels that move from a path to the path of a word.
func walkTable(w io.Writer, root *node, format string) {
	root.each(func(n *node) {
		for _, s := range n.subs {
			for _, word := range s.words() {
				putf(w, format, n.path, word, s.path)
			}
		}
	})
}

func bash(w io.Writer, root *node) {
	spellings, by := valueOptions(root)
	putf(w, "# bash completion for %s; generated by \"%s completion bash\"\n", program, program)
	putf(w, "_%s() {\n", program)
	put(w, "\tlocal cur=\"${COMP_WORDS[COMP_CWORD]}\" prev=\"\" path=\"\" cmds=\"\" opts=\"\" i word\n")
	put(w, "\t((COMP_CWORD > 0)) && prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n")
	put(w, "\tCOMPREPLY=()\n")
	put(w, "\tfor ((i = 1; i < COMP_CWORD; i++)); do\n\t\tword=\"${COMP_WORDS[i]}\"\n\t\tcase \"$word\" in\n")
	if len(spellings) > 0 {
		putf(w, "\t\t%s) ((i++)); continue ;;\n", strings.Join(spellings, "|"))
	}
	put(w, "\t\t-*) continue ;;\n\t\tesac\n\t\tcase \"$path|$word\" in\n")
	walkTable(w, root, "\t\t'%s|%s') path='%s' ;;\n")
	put(w, "\t\tesac\n\tdone\n")
	put(w, "\tcase \"$prev\" in\n")
	for _, s := range spellings {
		o := by[s]
		switch {
		case len(o.choices) > 0:
			putf(w, "\t%s)\n\t\tCOMPREPLY=($(compgen -W %s -- \"$cur\")); return 0 ;;\n", s, quoteSh(joinWords(o.choices)))
		case o.file:
			putf(w, "\t%s)\n\t\tCOMPREPLY=($(compgen -f -- \"$cur\")); return 0 ;;\n", s)
		default:
			putf(w, "\t%s)\n\t\treturn 0 ;;\n", s)
		}
	}
	put(w, "\tesac\n")
	put(w, "\tcase \"$path\" in\n")
	root.each(func(n *node) {
		putf(w, "\t'%s') cmds=%s; opts=%s ;;\n", n.path, quoteSh(joinWords(subWords(n))), quoteSh(joinWords(optionWords(effective(root, n)))))
	})
	put(w, "\tesac\n")
	put(w, "\tif [[ \"$cur\" == -* ]]; then\n\t\tCOMPREPLY=($(compgen -W \"$opts\" -- \"$cur\"))\n\telse\n")
	put(w, "\t\tCOMPREPLY=($(compgen -W \"$cmds\" -- \"$cur\"))\n\t\t[[ -z \"$cmds\" ]] && COMPREPLY+=($(compgen -f -- \"$cur\"))\n\tfi\n")
	put(w, "\treturn 0\n}\n")
	putf(w, "complete -o filenames -F _%s %s\n", program, program)
}

func zshFunc(n *node) string {
	if n.path == "" {
		return "_" + program
	}
	return "_" + program + "_" + strings.NewReplacer("/", "_", "-", "_").Replace(n.path)
}

func zsh(w io.Writer, root *node) {
	putf(w, "#compdef %s\n# zsh completion for %s; generated by \"%s completion zsh\"\n", program, program, program)
	root.each(func(n *node) {
		putf(w, "%s() {\n", zshFunc(n))
		put(w, "\tlocal context state state_descr line\n\ttypeset -A opt_args\n\tlocal -a cmds\n")
		put(w, "\t_arguments -C \\\n")
		for _, o := range effective(root, n) {
			desc := "[" + zshText(o.description) + "]"
			spec := ""
			switch {
			case len(o.choices) > 0:
				spec = ":" + o.long + ":(" + strings.Join(o.choices, " ") + ")"
			case o.file:
				spec = ":file:_files"
			case o.takesValue:
				spec = ":" + o.long + ": "
			}
			if o.short != "" {
				putf(w, "\t\t'(-%s --%s)'{-%s,--%s}%s \\\n", o.short, o.long, o.short, o.long, quoteSh(desc+spec))
			} else {
				putf(w, "\t\t%s \\\n", quoteSh("--"+o.long+desc+spec))
			}
		}
		if len(n.subs) > 0 {
			put(w, "\t\t'1: :->cmds' \\\n\t\t'*:: :->args'\n")
			put(w, "\tcase $state in\n\tcmds)\n\t\tcmds=(")
			var items []string
			for _, s := range n.subs {
				for _, word := range s.words() {
					items = append(items, quoteSh(strings.ReplaceAll(word, ":", `\:`)+":"+zshText(s.description)))
				}
			}
			put(w, strings.Join(items, " "))
			put(w, ")\n\t\t_describe 'command' cmds ;;\n\targs)\n\t\tcase $words[1] in\n")
			for _, s := range n.subs {
				putf(w, "\t\t%s) %s ;;\n", strings.Join(s.words(), "|"), zshFunc(s))
			}
			put(w, "\t\tesac ;;\n\tesac\n")
		} else {
			put(w, "\t\t'*:argument:_files'\n")
		}
		put(w, "}\n")
	})
	putf(w, "%s \"$@\"\n", zshFunc(root))
}

func fish(w io.Writer, root *node) {
	spellings, _ := valueOptions(root)
	putf(w, "# fish completion for %s; generated by \"%s completion fish\"\n", program, program)
	put(w, "function __ligo_path --description 'the command path of the command line so far'\n")
	put(w, "\tset -l path ''\n\tset -l skip 0\n\tset -l words (commandline -opc)\n\tset -e words[1]\n\tfor word in $words\n")
	put(w, "\t\tif test $skip -eq 1\n\t\t\tset skip 0\n\t\t\tcontinue\n\t\tend\n\t\tswitch $word\n")
	if len(spellings) > 0 {
		var q []string
		for _, s := range spellings {
			q = append(q, quoteFish(s))
		}
		putf(w, "\t\t\tcase %s\n\t\t\t\tset skip 1\n", strings.Join(q, " "))
	}
	put(w, "\t\t\tcase '-*'\n\t\t\t\tcontinue\n\t\tend\n\t\tswitch \"$path|$word\"\n")
	walkTable(w, root, "\t\t\tcase '%s|%s'\n\t\t\t\tset path '%s'\n")
	put(w, "\t\tend\n\tend\n\techo $path\nend\n")
	root.each(func(n *node) {
		at := fmt.Sprintf("test (__ligo_path) = %s", quoteFish(n.path))
		for _, s := range n.subs {
			for _, word := range s.words() {
				putf(w, "complete -c %s -n %s -a %s -d %s\n", program, quoteFish(at), quoteFish(word), quoteFish(s.description))
			}
		}
		for _, o := range n.options {
			line := fmt.Sprintf("complete -c %s -n %s -l %s", program, quoteFish(descend(n)), o.long)
			if o.short != "" {
				line += " -s " + o.short
			}
			line += " -d " + quoteFish(o.description)
			switch {
			case len(o.choices) > 0:
				line += " -x -a " + quoteFish(joinWords(o.choices))
			case o.file:
				line += " -r -F"
			case o.takesValue:
				line += " -x"
			}
			put(w, line+"\n")
		}
	})
}

// descend returns the fish condition under which a node's own options apply:
// the node and everything below it. The root's options apply everywhere.
func descend(n *node) string {
	if n.path == "" {
		return "true"
	}
	return "string match -q -- " + quoteFish(n.path+"*") + " (__ligo_path)"
}

func powershell(w io.Writer, root *node) {
	spellings, by := valueOptions(root)
	putf(w, "# PowerShell completion for %s; generated by \"%s completion powershell\"\n", program, program)
	put(w, "$script:ligoNodes = @{\n")
	root.each(func(n *node) {
		var subs, opts []string
		for _, s := range n.subs {
			for _, word := range s.words() {
				subs = append(subs, "@("+quotePS(word)+", "+quotePS(s.description)+")")
			}
		}
		for _, o := range effective(root, n) {
			for _, sp := range o.spellings() {
				opts = append(opts, "@("+quotePS(sp)+", "+quotePS(o.description)+")")
			}
		}
		putf(w, "\t%s = @{ subs = @(%s); opts = @(%s) }\n", quotePS(n.path), strings.Join(subs, ", "), strings.Join(opts, ", "))
	})
	put(w, "}\n$script:ligoWalk = @{\n")
	walkTable(w, root, "\t'%s|%s' = '%s'\n")
	put(w, "}\n$script:ligoValues = @{\n")
	for _, s := range spellings {
		o := by[s]
		var vals []string
		for _, c := range o.choices {
			vals = append(vals, quotePS(c))
		}
		putf(w, "\t%s = @(%s)\n", quotePS(s), strings.Join(vals, ", "))
	}
	put(w, "}\n")
	putf(w, "Register-ArgumentCompleter -Native -CommandName %s -ScriptBlock {\n", program)
	put(w, "\tparam($wordToComplete, $commandAst, $cursorPosition)\n")
	put(w, "\t$words = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })\n")
	put(w, "\t$done = if ($wordToComplete -eq '') { $words.Count } else { $words.Count - 1 }\n")
	put(w, "\t$path = ''\n\t$skip = $false\n")
	put(w, "\tfor ($i = 1; $i -lt $done; $i++) {\n\t\t$word = $words[$i]\n")
	put(w, "\t\tif ($skip) { $skip = $false; continue }\n")
	put(w, "\t\tif ($script:ligoValues.ContainsKey($word)) { $skip = $true; continue }\n")
	put(w, "\t\tif ($word.StartsWith('-')) { continue }\n")
	put(w, "\t\t$key = \"$path|$word\"\n\t\tif ($script:ligoWalk.ContainsKey($key)) { $path = $script:ligoWalk[$key] }\n\t}\n")
	put(w, "\t$previous = if ($done -ge 1) { $words[$done - 1] } else { '' }\n")
	put(w, "\t$candidates = @()\n")
	put(w, "\tif ($script:ligoValues.ContainsKey($previous) -and $script:ligoValues[$previous].Count -gt 0) {\n")
	put(w, "\t\t$candidates = @($script:ligoValues[$previous] | ForEach-Object { , @($_, $_) })\n\t} elseif ($script:ligoValues.ContainsKey($previous)) {\n\t\treturn\n\t} else {\n")
	put(w, "\t\t$node = $script:ligoNodes[$path]\n")
	put(w, "\t\t$candidates = if ($wordToComplete.StartsWith('-')) { $node.opts } else { $node.subs }\n\t}\n")
	put(w, "\t$candidates | Where-Object { $_[0] -like \"$wordToComplete*\" } | ForEach-Object {\n")
	put(w, "\t\t[System.Management.Automation.CompletionResult]::new($_[0], $_[0], 'ParameterValue', $_[1])\n\t}\n}\n")
}
