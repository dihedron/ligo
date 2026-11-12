// Package docs holds the tests that keep the release documents complete
// (.specs/ligo-docs.md): the documents themselves are Markdown, built to PDF
// by build.sh.
package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/instances"
)

const (
	configurationReference = "setup-guide/11-configuration-reference.md"
	errorReference         = "operators-guide/05-error-reference.md"
	monitoring             = "operators-guide/02-monitoring.md"
)

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// goSources is the text of the non-test Go files under dir.
func goSources(t *testing.T, dir string) string {
	t.Helper()
	var all strings.Builder
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, err := os.ReadFile(filepath.Clean(path))
		all.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return all.String()
}

// matches is the sorted, distinct first groups of re in text.
func matches(re, text string) []string {
	var out []string
	for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// keys lists the yaml paths of a configuration type.
func keys(t reflect.Type, prefix string, seen map[reflect.Type]bool, out *[]string) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	defer delete(seen, t)
	for i := range t.NumField() {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag == "" || tag == "-" {
			if f.Anonymous {
				keys(f.Type, prefix, seen, out)
			}
			continue
		}
		*out = append(*out, prefix+tag)
		keys(f.Type, prefix+tag+".", seen, out)
	}
}

// TestConfigurationReferenceIsComplete: every key of server.yaml, by its path.
func TestConfigurationReferenceIsComplete(t *testing.T) {
	var all []string
	keys(reflect.TypeFor[config.Config](), "", map[reflect.Type]bool{}, &all)
	if len(all) < 100 {
		t.Fatalf("only %d keys: the test is broken", len(all))
	}
	doc := read(t, configurationReference)
	for _, key := range all {
		if !strings.Contains(doc, "`"+key+"`") {
			t.Errorf("%s: `%s` is not documented", configurationReference, key)
		}
	}
}

// TestPluginConfigurationIsComplete: every field of each shipped plugin's
// configuration, from its JSON schema.
func TestPluginConfigurationIsComplete(t *testing.T) {
	doc := read(t, configurationReference)
	for _, name := range []string{"openldap", "postgres", "vault"} {
		schema := read(t, "../cmd/plugins/ligo-plugin-"+name+"/schemas/config.json")
		properties := schema[strings.Index(schema, `"properties"`):]
		fields := matches(`"([a-z_]+)":\s*\{\s*"type"`, properties)
		if len(fields) < 4 {
			t.Fatalf("%s: only %d fields: the test is broken", name, len(fields))
		}
		for _, field := range fields {
			if field != "items" && !strings.Contains(doc, "`"+field+"`") { // items: the schema's own keyword
				t.Errorf("%s: the field `%s` of %s is not documented", configurationReference, field, name)
			}
		}
	}
}

// TestErrorReferenceIsComplete: every problem slug of the admin API, and every
// error code of the shipped plugins.
func TestErrorReferenceIsComplete(t *testing.T) {
	doc := read(t, errorReference)
	internal := goSources(t, "../internal")
	slugs := matches(`(?:refuse\([0-9a-zA-Z.]+, |problem\(w, [a-zA-Z.]+, |Slug: )"([a-z-]+)"`, internal)
	codes := matches(`pluginsdk\.Error\(codes\.[A-Za-z]+, "([A-Z_]+)"`, goSources(t, "../cmd/plugins"))
	if len(slugs) < 20 || len(codes) < 15 {
		t.Fatalf("%d slugs, %d codes: the test is broken", len(slugs), len(codes))
	}
	for _, id := range append(slugs, codes...) {
		if !strings.Contains(doc, "`"+id+"`") {
			t.Errorf("%s: `%s` is not documented", errorReference, id)
		}
	}
}

// TestMonitoringIsComplete: every metric.
func TestMonitoringIsComplete(t *testing.T) {
	doc := read(t, monitoring)
	metrics := matches(`"(ligo_[a-z_]+)"`, goSources(t, "../internal/metrics")+goSources(t, "../internal/server/workloadhttp"))
	if len(metrics) < 10 {
		t.Fatalf("only %d metrics: the test is broken", len(metrics))
	}
	for _, metric := range metrics {
		if metric != "ligo_bindings_changed" && !strings.Contains(doc, "`"+metric) {
			t.Errorf("%s: `%s` is not documented", monitoring, metric)
		}
	}
}

var separator = regexp.MustCompile(`^\|( *:?-+:? *\|)+$`)

// TestTablesSetColumnWidths: the dashes set a table's proportions, so equal
// ones give equal columns, which rarely fit.
func TestTablesSetColumnWidths(t *testing.T) {
	files, err := filepath.Glob("*/[0-9][0-9]-*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("no chapters (%v)", err)
	}
	for _, file := range files {
		for i, line := range strings.Split(read(t, file), "\n") {
			if !separator.MatchString(strings.TrimSpace(line)) {
				continue
			}
			lengths := map[int]bool{}
			for _, cell := range strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|") {
				lengths[len(strings.Trim(strings.TrimSpace(cell), ":"))] = true
			}
			if len(lengths) == 1 {
				t.Errorf("%s:%d: the table's columns all have the same width: set their proportions with the dashes' lengths", file, i+1)
			}
		}
	}
}

// charterDefinition is the first sentence of the charter's definition, which
// every released guide must carry, so that the term never surprises a
// reader (.specs/ligo_specification.md §3.9).
const charterDefinition = "The **charter** is the set of rules every jurisdiction must comply with"

func TestCharterIsDefined(t *testing.T) {
	for _, dir := range []string{"setup-guide", "architecture", "operators-guide"} {
		files, err := filepath.Glob(dir + "/[0-9][0-9]-*.md")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range files {
			found = found || strings.Contains(read(t, f), charterDefinition)
		}
		if !found {
			t.Errorf("%s: no chapter defines the charter (%q)", dir, charterDefinition)
		}
	}
}

// TestPlanningExamples loads every blueprint's server.yaml of the planning
// guide with the real configuration loader and its static rules, so that the
// excerpts the guide shows cannot drift from the code
// (.specs/ligo-planning-guide.md §5).
func TestPlanningExamples(t *testing.T) {
	files, err := filepath.Glob("planning-guide/examples/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no examples in planning-guide/examples")
	}
	placeholder := regexp.MustCompile(`<64-hex-sha256-of-[a-z-]+>`)
	anyEnv := func(string) (string, bool) { return "ligo-1", true }
	for _, f := range files {
		cfg, err := config.Parse([]byte(placeholder.ReplaceAllString(read(t, f), strings.Repeat("ab", 32))))
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if err := config.Validate(cfg, config.Options{LookupEnv: anyEnv}); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		checkInstances(t, cfg, filepath.Join(filepath.Dir(f), "instances", filepath.Base(f)))
	}
}

// checkInstances checks an example's instances against its configuration:
// the static checks, the bounds and the wiring (.specs/ligo-instances.md §6).
func checkInstances(t *testing.T, cfg *config.Config, manifest string) {
	t.Helper()
	env, err := instances.NewEnv(cfg)
	if err != nil {
		t.Fatalf("%s: %v", manifest, err)
	}
	set, err := instances.LoadManifest(manifest)
	if err != nil {
		t.Fatalf("%s: %v", manifest, err)
	}
	for _, d := range set.All() {
		if err := env.Check(d); err != nil {
			t.Errorf("%s: %s: %v", manifest, d.Metadata.Name, err)
		}
		if err := env.Bounded(d, nil); err != nil {
			t.Errorf("%s: %s: %v", manifest, d.Metadata.Name, err)
		}
	}
	for _, p := range set.List(instances.Platform) {
		for k, w := range map[instances.Kind]*instances.Wiring{instances.IdentityProvider: p.IdentityProvider, instances.SecretStore: p.SecretStore} {
			if in, ok := set.Get(k, w.Instance); !ok || in.Type != w.Type || in.Metadata.Realm != p.Metadata.Realm {
				t.Errorf("%s: platform %s: %s %s/%s is not an instance of its realm", manifest, p.Metadata.Name, k, w.Type, w.Instance)
			}
		}
	}
}
