package adminhttp

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestOpenAPI checks that the OpenAPI document lists exactly the routes
// the server registers, and that its local references resolve. A {op}
// wildcard stands for the state changes it accepts.
func TestOpenAPI(t *testing.T) {
	data, err := os.ReadFile("../../../api/openapi/admin.v1alpha1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var documented []string
	for path, item := range doc["paths"].(map[string]any) {
		for method := range item.(map[string]any) {
			if method != "parameters" {
				documented = append(documented, strings.ToUpper(method)+" "+path)
			}
		}
	}
	var routed []string
	for _, p := range (&Server{}).routes().patterns {
		if strings.HasSuffix(p, "/{op}") {
			for _, op := range []string{"deprecate", "reactivate", "retire"} {
				routed = append(routed, strings.TrimSuffix(p, "{op}")+op)
			}
			continue
		}
		routed = append(routed, p)
	}
	slices.Sort(documented)
	slices.Sort(routed)
	for _, r := range routed {
		if !slices.Contains(documented, r) {
			t.Errorf("routed, not in the OpenAPI document: %s", r)
		}
	}
	for _, d := range documented {
		if !slices.Contains(routed, d) {
			t.Errorf("in the OpenAPI document, not routed: %s", d)
		}
	}

	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok && strings.HasPrefix(ref, "#/") {
				var cur any = doc
				for _, key := range strings.Split(ref[2:], "/") {
					m, _ := cur.(map[string]any)
					cur = m[key]
				}
				if cur == nil {
					t.Errorf("unresolved reference %s", ref)
				}
			}
			for _, x := range v {
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(doc)
}
