package command

import (
	"testing"

	"github.com/jessevdk/go-flags"
)

// TestCommandTree enforces the convention of AGENTS.md: ligo <object> <verb>.
// Only apply (the kind comes from the manifest), migrate, serve and version
// stand alone; every other root command is an object with verbs.
func TestCommandTree(t *testing.T) {
	standalone := map[string]bool{"apply": true, "migrate": true, "serve": true, "version": true}
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
