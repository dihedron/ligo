package ui

import (
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
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
