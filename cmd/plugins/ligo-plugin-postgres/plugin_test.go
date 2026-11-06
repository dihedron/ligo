package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/status"
)

const goodConfig = `{"host":"db.lab","port":5432,"database":"ledger","grantable_roles":["RO","RW"],"allowed_endpoints":["db.lab:5432"],
	"bootstrap_credential":{"source":"vault","address":"https://v.lab","auth_mount":"m","role":"r","jwt_audience":"a","kv_path":"kv/data/x"}}`

// errorCode is the PluginErrorDetail code of err, and whether it is retryable.
func errorCode(t *testing.T, err error) (string, bool) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok || len(st.Details()) != 1 {
		t.Fatalf("not a plugin error: %v", err)
	}
	d := st.Details()[0].(*pluginv1.PluginErrorDetail)
	return d.GetCode(), d.GetRetryable()
}

// TestParseConfig: PG-1, every field's rule names the field.
func TestParseConfig(t *testing.T) {
	if _, err := parseConfig([]byte(goodConfig), pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL); err != nil {
		t.Fatal(err)
	}
	set := func(field, value string) string {
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(goodConfig), &m)
		if value == "" {
			delete(m, field)
		} else {
			m[field] = json.RawMessage(value)
		}
		out, _ := json.Marshal(m)
		return string(out)
	}
	for name, tc := range map[string]struct {
		config string
		mode   pluginv1.IdentityMode
		want   string
	}{
		"unknown field":     {set("nope", `1`), 0, "nope"},
		"no host":           {set("host", ""), 0, "host"},
		"port":              {set("port", `70000`), 0, "port"},
		"database":          {set("database", `"a b"`), 0, "database"},
		"no roles":          {set("grantable_roles", ""), 0, "grantable_roles"},
		"bad role":          {set("grantable_roles", `["a;b"]`), 0, "grantable_roles"},
		"endpoint":          {set("allowed_endpoints", `["other:1"]`), 0, "allowed_endpoints"},
		"group":             {set("directory_group", `"a b"`), 0, "directory_group"},
		"no group":          {goodConfig, pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR, "directory_group"},
		"no credential":     {set("bootstrap_credential", ""), 0, "bootstrap_credential"},
		"no kv_path":        {set("bootstrap_credential", `{"source":"vault"}`), 0, "kv_path"},
		"invalid bootstrap": {set("bootstrap_credential", `{"source":"nope","kv_path":"x"}`), 0, ""},
		"ca_file":           {set("ca_file", `"/does/not/exist"`), 0, "ca_file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig([]byte(tc.config), tc.mode)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v, want %q", err, tc.want)
			}
		})
	}
}

// testPlugin has one instance that fails the test if it connects.
func testPlugin(t *testing.T) *plugin {
	t.Helper()
	c, err := parseConfig([]byte(goodConfig), 0)
	if err != nil {
		t.Fatal(err)
	}
	return &plugin{instances: map[string]*instance{"pg": {config: *c, dial: func(context.Context) (*pgx.Conn, error) {
		t.Error("connected")
		return nil, errors.New("no database here")
	}}}}
}

// TestValidateNoStatement: PG-2, refused without a connection.
func TestValidateNoStatement(t *testing.T) {
	ctx := context.Background()
	p := testPlugin(t)
	def := []byte(`{"database":"ledger","schema":"s"}`)
	level := func(roles string) []*pluginv1.AccessLevelInput {
		return []*pluginv1.AccessLevelInput{{Name: "l", GrantsJson: []byte(`{"roles":` + roles + `}`)}}
	}
	vt, err := p.ValidateTarget(ctx, &pluginv1.ValidateTargetRequest{Instance: "pg", DefinitionJson: def, AccessLevels: level(`["RW","RO","RO"]`)})
	if err != nil || !vt.GetValid() || strings.Join(vt.GetAccessLevels()[0].GetPrivileges(), ",") != "role:RO,role:RW" {
		t.Fatalf("%v %v", vt, err)
	}
	for name, r := range map[string]*pluginv1.ValidateTargetRequest{
		"another database": {Instance: "pg", DefinitionJson: []byte(`{"database":"x","schema":"s"}`)},
		"bad schema":       {Instance: "pg", DefinitionJson: []byte(`{"database":"ledger","schema":"a;b"}`)},
		"unknown field":    {Instance: "pg", DefinitionJson: []byte(`{"database":"ledger","schema":"s","x":1}`)},
		"out of bounds":    {Instance: "pg", DefinitionJson: def, AccessLevels: level(`["DBA"]`)},
		"no roles":         {Instance: "pg", DefinitionJson: def, AccessLevels: level(`[]`)},
	} {
		if vt, err := p.ValidateTarget(ctx, r); err != nil || vt.GetValid() {
			t.Errorf("%s: valid (%v)", name, err)
		}
	}
	grants := []byte(`{"roles":["RO"]}`)
	vb, err := p.ValidateBinding(ctx, &pluginv1.ValidateBindingRequest{Instance: "pg", DefinitionJson: def, AccessLevelGrantsJson: grants,
		ParametersJson: []byte(`{"connectionLimit":5}`)})
	if err != nil || !vb.GetValid() || strings.Join(vb.GetPrivileges(), ",") != "role:RO" {
		t.Fatalf("%v %v", vb, err)
	}
	for name, r := range map[string]*pluginv1.ValidateBindingRequest{
		"a role in the parameters": {Instance: "pg", DefinitionJson: def, AccessLevelGrantsJson: grants, ParametersJson: []byte(`{"roles":["RW"]}`)},
		"limit":                    {Instance: "pg", DefinitionJson: def, AccessLevelGrantsJson: grants, ParametersJson: []byte(`{"connectionLimit":1001}`)},
		"out of bounds":            {Instance: "pg", DefinitionJson: def, AccessLevelGrantsJson: []byte(`{"roles":["DBA"]}`)},
		"definition":               {Instance: "pg", DefinitionJson: []byte(`{`), AccessLevelGrantsJson: grants},
	} {
		if vb, err := p.ValidateBinding(ctx, r); err != nil || vb.GetValid() {
			t.Errorf("%s: valid (%v)", name, err)
		}
	}
	if _, err := p.ValidateTarget(ctx, &pluginv1.ValidateTargetRequest{Instance: "nope"}); err == nil {
		t.Error("an unknown instance")
	}
}

// TestBindingGrammar: PG-3, refused before any statement.
func TestBindingGrammar(t *testing.T) {
	ctx := context.Background()
	p := testPlugin(t)
	id := "01a1ac77-0d46-7515-bbf4-24f877af4b2b"
	spec := []byte(`{"database":"ledger","schema":"s","roles":["RO"],"connectionLimit":0}`)
	local := &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL}
	for name, tc := range map[string]struct {
		b    *pluginv1.BindingContext
		want string
	}{
		"principal": {&pluginv1.BindingContext{BindingId: id, DerivedPrincipalName: `x"; DROP ROLE y; --`}, "INVALID_PRINCIPAL"},
		"id":        {&pluginv1.BindingContext{BindingId: "'; DROP", DerivedPrincipalName: "bnd_a"}, "INVALID_BINDING"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := p.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "pg", Binding: tc.b, Identity: local, RequestedSpecJson: spec})
			if code, _ := errorCode(t, err); code != tc.want {
				t.Errorf("EnsureTarget: %s", code)
			}
			_, err = p.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg", Binding: tc.b})
			if code, _ := errorCode(t, err); code != tc.want {
				t.Errorf("CleanupTarget: %s", code)
			}
		})
	}
	good := &pluginv1.BindingContext{BindingId: id, DerivedPrincipalName: "bnd_a"}
	_, err := p.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "pg", Binding: good, Identity: local,
		RequestedSpecJson: []byte(`{"roles":["DBA"]}`)})
	if code, retry := errorCode(t, err); code != "PRIVILEGE_OUT_OF_BOUNDS" || retry {
		t.Errorf("a bound tightened: %s %v", code, retry)
	}
	_, err = p.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "pg", Binding: good, Identity: local, RequestedSpecJson: []byte(`{`)})
	if code, _ := errorCode(t, err); code != "INVALID_SPEC" {
		t.Errorf("a bad spec: %s", code)
	}
	_, err = p.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "pg", Binding: good, RequestedSpecJson: spec,
		Identity: &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_SVID}})
	if code, _ := errorCode(t, err); code != "INCOMPATIBLE_IDENTITY_MODE" {
		t.Errorf("SVID: %s", code)
	}
}

// TestFailure: PG-11, each SQLSTATE's code and retryability.
func TestFailure(t *testing.T) {
	for state, want := range map[string]struct {
		code  string
		retry bool
	}{
		"":      {"TARGET_UNAVAILABLE", true},
		"28P01": {"BOOTSTRAP_CREDENTIAL_REJECTED", true},
		"28000": {"BOOTSTRAP_CREDENTIAL_REJECTED", true},
		"08006": {"TARGET_UNAVAILABLE", true},
		"57P01": {"TARGET_UNAVAILABLE", true},
		"53300": {"TARGET_UNAVAILABLE", true},
		"40001": {"TARGET_BUSY", true},
		"55P03": {"TARGET_BUSY", true},
		"42710": {"TARGET_BUSY", true},
		"23505": {"TARGET_BUSY", true},
		"42704": {"ROLE_NOT_FOUND", false},
		"42501": {"TARGET_ACCESS_DENIED", false},
		"2BP01": {"ROLE_OWNS_OBJECTS", false},
		"42601": {"TARGET_REJECTED", false},
	} {
		err := errors.New("no answer")
		if state != "" {
			err = &pgconn.PgError{Code: state, Message: "secret text from the server"}
		}
		failed := failure(err)
		code, retry := errorCode(t, failed)
		if code != want.code || retry != want.retry {
			t.Errorf("%q: %s %v, want %+v", state, code, retry, want)
		}
		if strings.Contains(failed.Error(), "secret text") {
			t.Errorf("%q: the server's text reached the error", state)
		}
	}
	if code, retry := errorCode(t, failure(fmt.Errorf("%w: x", errCredential))); code != "BOOTSTRAP_CREDENTIAL_UNAVAILABLE" || !retry {
		t.Errorf("credential: %s %v", code, retry)
	}
}

// TestScramVerifier: the form PostgreSQL accepts, computed from RFC 7677's
// test vector for the keys.
func TestScramVerifier(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	got, err := scramVerifier("pencil", salt)
	if err != nil {
		t.Fatal(err)
	}
	const want = "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
	if got != want {
		t.Errorf("%s\nwant %s", got, want)
	}
	password, verifier, err := newPassword(40)
	if err != nil || len(password) != 40 || strings.Contains(verifier, password) || strings.ContainsAny(verifier, `'\`) {
		t.Errorf("%q %q %v", password, verifier, err)
	}
	if minPassword("64") != 64 || minPassword("8") != 32 || minPassword("") != 32 {
		t.Error("password_length")
	}
}

// TestHealth: PG-12, not serving with a fixed message; and the forms.
func TestHealth(t *testing.T) {
	c, _ := parseConfig([]byte(goodConfig), 0)
	p := &plugin{instances: map[string]*instance{"pg": {config: *c, dial: func(context.Context) (*pgx.Conn, error) {
		return nil, &pgconn.PgError{Code: "28P01", Message: "secret"}
	}}}}
	h, err := p.Health(context.Background(), &pluginv1.HealthRequest{Instance: "pg"})
	if err != nil || h.GetServing() || h.GetPublicMessage() == "" || strings.Contains(h.GetPublicMessage(), "secret") {
		t.Errorf("%v %v", h, err)
	}
	if _, err := p.Health(context.Background(), &pluginv1.HealthRequest{Instance: "nope"}); err == nil {
		t.Error("an unknown instance")
	}
	ui, err := p.GetUISchemas(context.Background(), &pluginv1.GetUISchemasRequest{Instance: "pg"})
	if err != nil || len(ui.GetAccessLevelGrants().GetFields()[0].GetOptions()) != 2 || ui.GetTargetDefinition().GetFields()[0].GetDefaultValue() != "ledger" {
		t.Errorf("%v %v", ui, err)
	}
	d, err := p.Describe(context.Background(), &pluginv1.DescribeRequest{})
	if err != nil || d.GetPlatformProvider().GetClientOutputSchemaJson() == "" {
		t.Errorf("%v %v", d, err)
	}
	if got := d.GetPlatformProvider().GetNamespaceField(); got != "schema" {
		t.Errorf("namespace_field %q", got)
	}
	for _, m := range d.GetPlatformProvider().GetAcceptedIdentityModes() {
		if m == pluginv1.IdentityMode_IDENTITY_MODE_SVID {
			t.Error("accepts SVID: §10")
		}
	}
}
