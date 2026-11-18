package completion

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	flags "github.com/jessevdk/go-flags"
)

type globals struct {
	Level  string `short:"l" long:"log-level" choice:"debug" choice:"info" default:"info" description:"logging verbosity"`
	Output string `short:"o" long:"output" choice:"table" choice:"json" choice:"yaml" default:"table" description:"it's an \"output\" $(touch pwned) format"`
}

type list struct {
	Limit int `long:"limit" description:"most items"`
}
type show struct {
	Args struct {
		ID string `positional-arg-name:"id"`
	} `positional-args:"yes"`
}
type source struct {
	List list `command:"list" alias:"ls" description:"List sources."`
	Show show `command:"show" description:"Show a source."`
}
type serve struct {
	Config string `short:"c" long:"config" value-name:"FILE" description:"the configuration file"`
}
type root struct {
	globals
	Source source `command:"source" alias:"src" description:"Sources: list, show."`
	Serve  serve  `command:"serve" description:"Run the daemon."`
}

func parser() *flags.Parser { return flags.NewParser(&root{}, flags.Default) }

func generate(t testing.TB, shell string) string {
	t.Helper()
	var out bytes.Buffer
	if err := Write(&out, shell, parser()); err != nil {
		t.Fatalf("%s: %v", shell, err)
	}
	return out.String()
}

var allShells = []string{"bash", "zsh", "fish", "powershell"}

// CX-1: every command, alias and option of the tree is in each script.
func TestEveryNodeIsListed(t *testing.T) {
	for _, sh := range allShells {
		t.Run(sh, func(t *testing.T) {
			script := generate(t, sh)
			for _, want := range []string{"source", "src", "list", "ls", "show", "serve", "log-level", "output", "limit", "config", "json", "yaml", "table", "help"} {
				if !strings.Contains(script, want) {
					t.Errorf("%s script lacks %q", sh, want)
				}
			}
		})
	}
}

func TestDeterministic(t *testing.T) {
	for _, sh := range allShells {
		first, second := generate(t, sh), generate(t, sh)
		if first != second {
			t.Errorf("%s output differs between runs", sh)
		}
	}
}

// CX-2: an unknown shell is an error that names the shells.
func TestUnknownShell(t *testing.T) {
	var out bytes.Buffer
	err := Write(&out, "tcsh", parser())
	if err == nil || !strings.Contains(err.Error(), "bash") || out.Len() != 0 {
		t.Errorf("got %v, %q", err, out.String())
	}
}

func have(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	return p
}

// CX-3 and T-K1: bash loads the script, completes through the tree, and runs nothing.
func TestBashCompletesTheTree(t *testing.T) {
	bash := have(t, "bash")
	dir := t.TempDir()
	script := filepath.Join(dir, "ligo.bash")
	if err := os.WriteFile(script, []byte(generate(t, "bash")), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := `source "$1"
complete -p ligo >/dev/null || { echo "no completion registered"; exit 3; }
c() { COMP_WORDS=("$@"); COMP_CWORD=$(( $# - 1 )); COMPREPLY=(); _ligo; printf '%s\n' "${COMPREPLY[*]}"; }
c ligo so
c ligo source l
c ligo source ""
c ligo --output ""
c ligo -o json source l
c ligo serve --c
c ligo source list --li
`
	cmd := exec.Command(bash, "-c", probe, "probe", script)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	want := []string{"source", "list ls", "list ls show", "table json yaml", "list ls", "--config", "--limit"}
	if len(lines) != len(want) {
		t.Fatalf("got %q", out)
	}
	for i := range want {
		if !strings.Contains(" "+lines[i]+" ", " "+strings.Fields(want[i])[0]+" ") || (len(strings.Fields(want[i])) > 1 && strings.TrimSpace(lines[i]) != want[i]) {
			t.Errorf("line %d: got %q, want %q", i+1, lines[i], want[i])
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Fatal("a description ran as a command")
	}
}

// CX-3: zsh and fish parse their scripts when they are installed.
func TestOtherShellsParse(t *testing.T) {
	for _, tc := range []struct {
		shell, bin string
		args       func(string) []string
	}{
		{"zsh", "zsh", func(f string) []string { return []string{"-n", f} }},
		{"fish", "fish", func(f string) []string { return []string{"--no-execute", f} }},
	} {
		t.Run(tc.shell, func(t *testing.T) {
			bin := have(t, tc.bin)
			f := filepath.Join(t.TempDir(), "script")
			if err := os.WriteFile(f, []byte(generate(t, tc.shell)), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(bin, tc.args(f)...).CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
}

// T-K1: no script runs a command to complete.
func TestScriptsRunNothing(t *testing.T) {
	for _, sh := range allShells {
		script := generate(t, sh)
		for _, bad := range []string{"eval ", "$(ligo", "`ligo", "ligo --", "Invoke-Expression"} {
			if strings.Contains(script, bad) {
				t.Errorf("%s script contains %q", sh, bad)
			}
		}
	}
}

// CX-5 and T-K2: a hostile description is quoted for every shell.
func FuzzQuote(f *testing.F) {
	for _, s := range []string{"plain", "it's", `a"b`, "$(touch x)", "`id`", `\`, "a\nb", "]:[", "''"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for name, q := range map[string]func(string) string{"bash": quoteSh, "zsh": quoteZsh, "fish": quoteFish, "powershell": quotePS} {
			out := q(s)
			if strings.ContainsAny(out, "\n\r") {
				t.Errorf("%s: a newline survives in %q", name, out)
			}
			if !strings.HasPrefix(out, "'") || !strings.HasSuffix(out, "'") {
				t.Errorf("%s: %q is not a single quoted word", name, out)
			}
		}
		if bash, err := exec.LookPath("bash"); err == nil && len(s) < 64 {
			out, err := exec.Command(bash, "-c", "printf %s "+quoteSh(s)).Output()
			if err != nil || string(out) != strings.NewReplacer("\n", " ", "\r", " ").Replace(strings.Join(strings.Fields(s), " ")) {
				t.Errorf("bash read %q back as %q (%v)", s, out, err)
			}
		}
	})
}
