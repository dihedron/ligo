package manpage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	flags "github.com/jessevdk/go-flags"
)

type list struct {
	Limit int `long:"limit" short:"n" description:"most items; it's .hidden \\ and -dashed"`
}
type show struct {
	Args struct {
		ID string `positional-arg-name:"id" required:"yes" description:"the item"`
	} `positional-args:"yes"`
}
type level struct {
	Add show `command:"add" description:"Add a level."`
}
type source struct {
	List  list  `command:"list" alias:"ls" description:"List sources."`
	Show  show  `command:"show" description:"Show a source."`
	Level level `command:"level" description:"Levels."`
}
type serve struct {
	Config string `short:"c" long:"config" value-name:"FILE" description:"the configuration file"`
}
type root struct {
	Source source `command:"source" alias:"src" description:"Sources: list, show."`
	Serve  serve  `command:"serve" description:"Run the daemon."`
}

func parser() *flags.Parser { return flags.NewParser(&root{}, flags.Default) }

// CX-6: one page per top-level command, with every subcommand, alias, argument and option.
func TestOnePagePerCommand(t *testing.T) {
	pages := Pages(parser())
	if len(pages) != 2 {
		t.Fatalf("got %d pages: %v", len(pages), keys(pages))
	}
	src, ok := pages["ligo-source.1"]
	if !ok {
		t.Fatalf("no ligo-source.1 in %v", keys(pages))
	}
	for _, want := range []string{"ligo\\-source", "list", "ls", "show", "level add", "\\-\\-limit", "\\-n", "id", "List sources."} {
		if !strings.Contains(src, want) {
			t.Errorf("ligo-source.1 lacks %q", want)
		}
	}
	if s := pages["ligo-serve.1"]; !strings.Contains(s, "\\-\\-config") || !strings.Contains(s, "FILE") {
		t.Errorf("ligo-serve.1 lacks its option:\n%s", s)
	}
}

func TestDeterministic(t *testing.T) {
	a, b := Pages(parser()), Pages(parser())
	for k := range a {
		if a[k] != b[k] {
			t.Errorf("%s differs between runs", k)
		}
	}
}

// the text is escaped for roff: no line starts with a control character
func TestRoffEscaping(t *testing.T) {
	for name, page := range Pages(parser()) {
		for _, line := range strings.Split(page, "\n") {
			if strings.HasPrefix(line, "'") || (strings.HasPrefix(line, ".") && !isRequest(line)) {
				t.Errorf("%s: a text line looks like a request: %q", name, line)
			}
		}
	}
}

func isRequest(line string) bool {
	for _, r := range []string{".TH", ".SH", ".SS", ".TP", ".PP", ".RS", ".RE", ".IP", ".B ", ".nf", ".fi", ".\\\"", ".br"} {
		if strings.HasPrefix(line, r) {
			return true
		}
	}
	return false
}

// groff renders every page without a warning.
func TestPagesRender(t *testing.T) {
	groff, err := exec.LookPath("groff")
	if err != nil {
		t.Skip("groff is not installed")
	}
	dir := t.TempDir()
	for name, page := range Pages(parser()) {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte(page), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(groff, "-man", "-ww", "-z", f).CombinedOutput(); err != nil || len(out) != 0 {
			t.Errorf("%s: %v: %s", name, err, out)
		}
	}
}

func keys(m map[string]string) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}
