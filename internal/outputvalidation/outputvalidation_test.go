package outputvalidation

import (
	"errors"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/flows"
)

const schema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
"properties":{
  "host":{"type":"string","x-ligo-endpoint":true},
  "urls":{"type":"array","items":{"type":"string","x-ligo-endpoint":true}},
  "raw":{"x-ligo-endpoint":true},
  "port":{"type":"integer"}},
"required":["host"]}`

func validator(t *testing.T) *Validator {
	t.Helper()
	al, err := flows.ParseAllowlist([]string{"pg.prod.internal:5432", "vault.prod.internal", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(schema, al)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestValidate: the size limit, the schema with its annotated endpoints,
// then the declared endpoints (§5.7, INV-13).
func TestValidate(t *testing.T) {
	v := validator(t)
	pg := []*pluginv1.Endpoint{{Host: "pg.prod.internal", Port: 5432}}
	for name, tc := range map[string]struct {
		output   string
		declared []*pluginv1.Endpoint
		want     string // "" for valid
	}{
		"valid":                    {`{"host":"pg.prod.internal:5432","port":5432,"urls":["https://vault.prod.internal:8200","https://vault.prod.internal","10.1.2.3:9000"]}`, pg, ""},
		"too large":                {`{"host":"pg.prod.internal:5432","pad":"` + strings.Repeat("x", 64<<10) + `"}`, nil, "64 KiB"},
		"not JSON":                 {`{"host":`, nil, "JSON"},
		"schema":                   {`{"port":"x"}`, nil, "host"},
		"endpoint not allowed":     {`{"host":"evil.example:5432"}`, nil, "/host"},
		"no port, entry with port": {`{"host":"pg.prod.internal"}`, nil, "/host"},
		"URL implies no port":      {`{"host":"pg.prod.internal:5432","urls":["https://pg.prod.internal"]}`, nil, "/urls/0"},
		"bad port":                 {`{"host":"pg.prod.internal:99999"}`, nil, "/host"},
		"annotated non-string":     {`{"host":"pg.prod.internal:5432","raw":5}`, nil, "/raw"},
		"declared not allowed":     {`{"host":"pg.prod.internal:5432"}`, []*pluginv1.Endpoint{{Host: "evil.example", Port: 443}}, "evil.example"},
		"declared without port":    {`{"host":"pg.prod.internal:5432"}`, []*pluginv1.Endpoint{{Host: "pg.prod.internal"}}, "pg.prod.internal"},
	} {
		t.Run(name, func(t *testing.T) {
			err := v.Validate([]byte(tc.output), tc.declared)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrFailed) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want ErrFailed mentioning %q", err, tc.want)
			}
		})
	}
}

// TestNew: an output schema that is empty or does not compile is refused,
// and so is a non-boolean x-ligo-endpoint.
func TestNew(t *testing.T) {
	for _, bad := range []string{"", `{"type":7}`, `{"properties":{"h":{"x-ligo-endpoint":"yes"}}}`} {
		if _, err := New(bad, flows.Allowlist{}); err == nil {
			t.Errorf("schema %q accepted", bad)
		}
	}
}
