package ui

import (
	"context"
	"fmt"
	"github.com/dihedron/ligo/internal/instances"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/targets"
)

// TestUISchemaRules: INV-12 when rendering a plugin's form, and the values
// read back with their JSON types.
func TestUISchemaRules(t *testing.T) {
	s := &Server{Logger: slog.New(slog.DiscardHandler)}
	var options []*pluginv1.UIFieldOption
	for i := range 600 {
		options = append(options, &pluginv1.UIFieldOption{Label: fmt.Sprint(i), Value: fmt.Sprint(i)})
	}
	form := &pluginv1.UIForm{Fields: []*pluginv1.UIFieldDescriptor{
		{JsonKey: "schema", Label: "Schema", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_TEXT, Required: true, ValidationRegex: `^[A-Z_]+$`},
		{JsonKey: "bad\" onfocus=\"x", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_TEXT},                // not a json_key: not rendered
		{JsonKey: "loose", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_TEXT, ValidationRegex: `(?<=x)`}, // not RE2: no pattern
		{JsonKey: "port", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_NUMBER},
		{JsonKey: "tls", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_BOOLEAN, DefaultValue: "true"},
		{JsonKey: "roles", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_MULTISELECT, Options: options},
		{JsonKey: "kind", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_UNSPECIFIED}, // unknown type: not rendered
	}}
	fs := s.fields(form, "def.", map[string]any{"schema": "LEDGER", "roles": []any{"3"}})
	var keys []string
	for _, f := range fs {
		keys = append(keys, f.Key)
	}
	if strings.Join(keys, " ") != "schema loose port tls roles" {
		t.Fatalf("rendered %v", keys)
	}
	if fs[0].Name != "def.schema" || fs[0].Value != "LEDGER" || fs[0].Pattern != `^[A-Z_]+$` || !fs[0].Required || fs[1].Pattern != "" {
		t.Errorf("text fields: %+v %+v", fs[0], fs[1])
	}
	if !fs[3].Checked || len(fs[4].Options) != maxOptions || !fs[4].Options[3].Selected || fs[4].Options[2].Selected {
		t.Errorf("checkbox default %v, options %d", fs[3].Checked, len(fs[4].Options))
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(url.Values{"def.schema": {" LEDGER "}, "def.port": {"5432"},
		"def.roles": {"1", "2"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got, err := s.values(r, form, "def.")
	if err != nil || fmt.Sprint(got) != "map[port:5432 roles:[1 2] schema:LEDGER tls:false]" {
		t.Errorf("values: %v %v", got, err)
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader("def.port=many"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := s.values(r, form, "def."); err == nil {
		t.Error("a number field accepted text")
	}
}

// TestRoleTemplateOptions: an option holding {namespace} is sent as the role of
// the schema submitted with it (.specs/ligo-tenancy.md §6); on an edit form it
// shows selected, and follows the schema if that changes.
func TestRoleTemplateOptions(t *testing.T) {
	form := &pluginv1.UIForm{Fields: []*pluginv1.UIFieldDescriptor{{JsonKey: "roles", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_MULTISELECT,
		Options: []*pluginv1.UIFieldOption{{Value: "{namespace}_read"}, {Value: "{namespace}_write"}, {Value: "SHARED"}}}}}
	submitted := map[string]any{"roles": []string{"{namespace}_read", "SHARED"}}
	expandNamespace(submitted, "acme_db01")
	if fmt.Sprint(submitted["roles"]) != "[acme_db01_read SHARED]" {
		t.Errorf("expanded %v", submitted["roles"])
	}
	grants := map[string]any{"roles": []any{"acme_db01_read", "SHARED"}} // as stored
	selectTemplates(form, grants, "acme_db01")
	s := &Server{Logger: slog.New(slog.DiscardHandler)}
	options := s.fields(form, "g.", grants)[0].Options
	if !options[0].Selected || options[1].Selected || !options[2].Selected {
		t.Errorf("selected %+v", options)
	}
	other := map[string]any{"roles": []any{"globex_db02_read"}}
	selectTemplates(form, other, "acme_db01")
	if options := s.fields(form, "g.", other)[0].Options; options[0].Selected {
		t.Errorf("another tenant's role selected %+v", options)
	}
	unset := map[string]any{"roles": []string{"{namespace}_read"}}
	expandNamespace(unset, "")
	if fmt.Sprint(unset["roles"]) != "[{namespace}_read]" {
		t.Errorf("no schema: %v, the plugin must refuse the placeholder", unset["roles"])
	}
}

// namespacedPlugin offers one template and holds the namespace in schema.
type namespacedPlugin struct{ Plugins }

func (namespacedPlugin) UISchemas(context.Context, string) (*pluginv1.GetUISchemasResponse, error) {
	return &pluginv1.GetUISchemasResponse{
		TargetDefinition: &pluginv1.UIForm{Fields: []*pluginv1.UIFieldDescriptor{{JsonKey: "schema", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_TEXT}}},
		AccessLevelGrants: &pluginv1.UIForm{Fields: []*pluginv1.UIFieldDescriptor{{JsonKey: "roles", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_MULTISELECT,
			Options: []*pluginv1.UIFieldOption{{Value: "{namespace}_read"}}}}},
	}, nil
}

// TestTargetFormExpandsNamespace: the form's submission and its edit form.
func TestTargetFormExpandsNamespace(t *testing.T) {
	s := &Server{Logger: slog.New(slog.DiscardHandler), Plugins: namespacedPlugin{}, Targets: &targets.Service{Rules: &targets.Rules{
		Instances:      instances.Fixed{Set: instances.NewSet(&instances.Definition{Kind: "Platform", Type: "postgres.v1", Metadata: instances.Metadata{Name: "pg"}})},
		NamespaceField: func(string) string { return "schema" }}}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(url.Values{"name": {"db01"}, "platform": {"pg"}, "def.schema": {"acme_db01"},
		"level.0.name": {"read"}, "level.0.grant.roles": {"{namespace}_read"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got, err := s.targetOf(r, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.AccessLevels[0].Grants) != `{"roles":["acme_db01_read"]}` {
		t.Errorf("grants %s", got.AccessLevels[0].Grants)
	}
	pf, err := s.platformFields(context.Background(), "pg", got)
	if err != nil {
		t.Fatal(err)
	}
	if o := pf.Levels[0].Grants[0].Options[0]; o.Value != "{namespace}_read" || !o.Selected {
		t.Errorf("edit form %+v", o)
	}
}
