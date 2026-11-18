package command

import (
	"os"
	"os/exec"
	"path/filepath"

	"bytes"
	"github.com/dihedron/ligo/internal/command/manpage"
	"strings"

	"github.com/dihedron/ligo/internal/command/completion"
	"testing"

	"github.com/jessevdk/go-flags"
)

// TestCommandTree enforces the convention of AGENTS.md: ligo <object> <verb>.
// Only apply (the kind comes from the manifest), migrate, serve and version
// stand alone; every other root command is an object with verbs.
func TestCommandTree(t *testing.T) {
	standalone := map[string]bool{"apply": true, "completion": true, "migrate": true, "serve": true, "version": true}
	removed := []string{"get", "list", "delete", "release", "retry", "rotate", "flows"}
	p := flags.NewParser(&Commands{}, flags.Default)
	for _, c := range p.Commands() {
		if !standalone[c.Name] && len(c.Commands()) == 0 {
			t.Errorf("ligo %s is a verb without an object: use ligo <object> %s", c.Name, c.Name)
		}
		for _, r := range removed {
			if c.Name == r {
				t.Errorf("ligo %s must not be a root command", r)
			}
		}
	}
	want := map[string][]string{
		"source":            {"list", "show", "delete", "release", "test", "deprecate", "reactivate"},
		"target":            {"list", "show", "delete", "release", "deprecate", "reactivate", "level", "revoke-bindings"},
		"binding":           {"list", "show", "delete", "release", "retry", "rotate", "flows"},
		"platform":          {"list", "show", "schema", "delete"},
		"identity-provider": {"list", "show", "delete"},
		"secret-store":      {"list", "show", "delete"},
		"cr":                {"show"},
		"account":           {"show"},
	}
	for group, verbs := range want {
		g := p.Find(group)
		if g == nil {
			t.Errorf("ligo %s is missing", group)
			continue
		}
		for _, v := range verbs {
			if g.Find(v) == nil {
				t.Errorf("ligo %s %s is missing", group, v)
			}
		}
		if g.Find("get") != nil {
			t.Errorf("ligo %s get: the verb is show", group)
		}
	}
}

// CX-1: every command, alias and option of the real tree is in each completion script.
func TestCompletionCoversTheTree(t *testing.T) {
	p := flags.NewParser(&Commands{}, flags.Default)
	var names []string
	var walk func(c *flags.Command)
	walk = func(c *flags.Command) {
		for _, s := range c.Commands() {
			names = append(names, s.Name)
			names = append(names, s.Aliases...)
			for _, o := range s.Options() {
				names = append(names, "--"+o.LongName)
			}
			walk(s)
		}
	}
	walk(p.Command)
	for _, o := range p.Command.Options() {
		names = append(names, "--"+o.LongName)
	}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		var out bytes.Buffer
		if err := completion.Write(&out, shell, p); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if !strings.Contains(out.String(), strings.TrimPrefix(n, "--")) { // fish writes -l name
				t.Errorf("the %s script lacks %q", shell, n)
			}
		}
	}
}

// CX-6: every top-level command has a page with its subcommands and options,
// and groff renders each one without a warning.
func TestManPagesCoverTheTree(t *testing.T) {
	p := flags.NewParser(&Commands{}, flags.Default)
	pages := manpage.Pages(p)
	dir := t.TempDir()
	for _, c := range p.Commands() {
		name := "ligo-" + c.Name + ".1"
		page, ok := pages[name]
		if !ok {
			t.Errorf("no page %s", name)
			continue
		}
		var walk func(*flags.Command, string)
		walk = func(c *flags.Command, prefix string) {
			for _, o := range c.Options() {
				if o.LongName == "server" || o.LongName == "ca-cert" || o.LongName == "spiffe-socket" || o.LongName == "server-id" || o.LongName == "username" || o.LongName == "password-file" || o.LongName == "approval-ref" || o.LongName == "automation-context" {
					continue // described once, in ligo(1)
				}
				if !strings.Contains(page, strings.ReplaceAll(o.LongName, "-", `\-`)) {
					t.Errorf("%s lacks --%s", name, o.LongName)
				}
			}
			for _, s := range c.Commands() {
				if !strings.Contains(page, strings.ReplaceAll(prefix+s.Name, "-", `\-`)) {
					t.Errorf("%s lacks the subcommand %s", name, prefix+s.Name)
				}
				walk(s, prefix+s.Name+" ")
			}
		}
		walk(c, "")
		if err := os.WriteFile(filepath.Join(dir, name), []byte(page), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if groff, err := exec.LookPath("groff"); err == nil {
		for name := range pages {
			if out, err := exec.Command(groff, "-man", "-ww", "-z", filepath.Join(dir, name)).CombinedOutput(); err != nil || len(out) != 0 {
				t.Errorf("groff %s: %v: %s", name, err, out)
			}
		}
	}
}

// CX-4: ligo(1) documents every top-level command and global option.
func TestManPageDocumentsTheCommands(t *testing.T) {
	md, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "man", "ligo.1.md"))
	if err != nil {
		t.Fatal(err)
	}
	page := strings.ReplaceAll(string(md), `\--`, "--")
	p := flags.NewParser(&Commands{}, flags.Default)
	for _, c := range p.Commands() {
		if !strings.Contains(page, "**"+c.Name+"**") {
			t.Errorf("ligo.1.md does not describe the command %s", c.Name)
		}
	}
	for _, o := range p.Command.Options() {
		if !strings.Contains(page, "**--"+o.LongName+"**") {
			t.Errorf("ligo.1.md does not describe --%s", o.LongName)
		}
	}
}
