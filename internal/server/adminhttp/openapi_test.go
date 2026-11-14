package adminhttp

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/santhosh-tekuri/jsonschema/v6"
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

// openAPI is the OpenAPI document, read once per test.
func openAPI(t *testing.T) (data []byte, doc map[string]any) {
	t.Helper()
	data, err := os.ReadFile("../../../api/openapi/admin.v1alpha1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return data, doc
}

// at follows keys down the document.
func at(t *testing.T, doc map[string]any, keys ...string) any {
	t.Helper()
	var cur any = doc
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok || m[k] == nil {
			t.Fatalf("the OpenAPI document has no %s", strings.Join(keys, "."))
		}
		cur = m[k]
	}
	return cur
}

// enumOf is the values of an enum of the document, as strings (null as "").
func enumOf(t *testing.T, doc map[string]any, keys ...string) []string {
	t.Helper()
	var out []string
	for _, v := range at(t, doc, append(keys, "enum")...).([]any) {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// TestOpenAPIEnums: the enums of the change request in the OpenAPI document
// are the database's (.specs/ligo-adminclient.md §3.4): a client generated
// from the document must not lack a state, a kind or a resource type the
// server can send.
func TestOpenAPIEnums(t *testing.T) {
	_, doc := openAPI(t)
	sql, err := os.ReadFile("../../../migrations/001_init_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	db := map[string][]string{}
	for _, m := range regexp.MustCompile(`(?s)CREATE TYPE (\w+)\s+AS ENUM\s*\(([^)]*)\)`).FindAllStringSubmatch(string(sql), -1) {
		db[m[1]] = regexp.MustCompile(`'([A-Z_]+)'`).FindAllString(m[2], -1)
		for i, v := range db[m[1]] {
			db[m[1]][i] = strings.Trim(v, "'")
		}
	}
	schemas := func(name string, keys ...string) []string {
		return enumOf(t, doc, append([]string{"components", "schemas", name}, keys...)...)
	}
	for name, tc := range map[string]struct {
		api []string
		db  string
	}{
		"ChangeRequestStatus":       {schemas("ChangeRequestStatus"), "change_request_status"},
		"ResourceType":              {schemas("ResourceType"), "resource_type"},
		"ChangeRequest.operation":   {schemas("ChangeRequest", "properties", "operation"), "change_request_op"},
		"ChangeRequest.kind":        {schemas("ChangeRequest", "properties", "kind"), "change_request_kind"},
		"ChangeRequest.consent":     {schemas("ChangeRequest", "properties", "consent"), "consent_rule"},
		"Side.basis":                {schemas("Side", "properties", "basis"), "approval_basis"},
		"Side.decision (with null)": {schemas("Side", "properties", "decision"), "side_decision"},
		"BindingPhase":              {schemas("BindingPhase"), "binding_phase"},
		"Binding.status.operation":  {schemas("Binding", "properties", "status", "properties", "operation"), "binding_operation"},
		"Stage.stage":               {schemas("Stage", "properties", "stage"), "binding_stage"},
		"Stage.status":              {schemas("Stage", "properties", "status"), "stage_status"},
		"ResourceState":             {schemas("ResourceState"), "lifecycle_state"},
	} {
		want := db[tc.db]
		if len(want) == 0 {
			t.Fatalf("no enum %s in the migration", tc.db)
		}
		got := slices.DeleteFunc(slices.Clone(tc.api), func(s string) bool { return s == "" })
		if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
			t.Errorf("%s: the OpenAPI document has %v, the database %s has %v", name, got, tc.db, want)
		}
	}
}

// TestOpenAPIChangeRequest: what the server sends for a change request
// satisfies the document's schema, in a single read, a filing and a list.
func TestOpenAPIChangeRequest(t *testing.T) {
	compile := compileOpenAPI(t)
	one := compile("/components/schemas/ChangeRequest")
	filed := compile("/components/responses/Filed/content/application~1json/schema")
	page := compile("/components/responses/ChangeRequestPage/content/application~1json/schema")

	id, requested := uuid.NewV7(), time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	decided := requested.Add(time.Minute)
	for name, r := range map[string]*changerequests.Request{
		"a pending binding": {ID: id, ResourceType: "BINDING", ResourceName: "b", Operation: "CREATE", Consent: "ALL", Status: "PENDING", Realm: "prod",
			SourceJurisdiction: "dc/a", TargetJurisdiction: "dc/b", PlatformJurisdiction: "dc/b", PayloadSHA256: "ab", PolicySHA256: "cd", RequestedBy: "olga",
			RequestedAt: requested, ExpiresAt: requested.Add(time.Hour), Payload: json.RawMessage(`{"name":"b"}`),
			Sides: []changerequests.Side{{Name: "SOURCE", Jurisdiction: "dc/a", Basis: "HUMAN"}, {Name: "TARGET", Jurisdiction: "dc/b", Basis: "AUTO", Decision: "APPROVED", DecidedBy: "dora", DecidedAt: &decided}}},
		"an applied platform": {ID: id, ResourceType: "PLATFORM", ResourceName: "p", Operation: "UPDATE", Consent: "ALL", Status: "APPLIED", OwnerJurisdiction: "dc/p",
			PayloadSHA256: "ab", PolicySHA256: "cd", RequestedBy: "ada", RequestedAt: requested, ExpiresAt: requested.Add(time.Hour),
			Sides: []changerequests.Side{{Name: "OWNER", Jurisdiction: "dc/p", Basis: "HUMAN", Decision: "APPROVED", DecidedBy: "ivy", DecidedAt: &decided}}},
		"a break-glass change": {ID: id, ResourceType: "TARGET", ResourceName: "t", Operation: "DELETE", Kind: changerequests.KindBreakGlass, Consent: "ANY",
			Status: "FAILED_TO_APPLY", OwnerJurisdiction: "dc/t", PayloadSHA256: "ab", PolicySHA256: "cd", RequestedBy: "ada", Justification: "incident",
			TTL: time.Hour, RequestedAt: requested, ExpiresAt: requested.Add(time.Hour)},
	} {
		d := dto(r, true)
		for what, tc := range map[string]struct {
			sch  *jsonschema.Schema
			body any
		}{
			"read":   {one, d},
			"filing": {filed, map[string]any{"changeRequest": d, "resource": nil}},
			"list":   {page, map[string]any{"items": []any{d}, "nextPageToken": nil}},
		} {
			raw, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			if err := tc.sch.Validate(v); err != nil {
				t.Errorf("%s, %s: %v\n%s", name, what, err, raw)
			}
		}
	}
}
