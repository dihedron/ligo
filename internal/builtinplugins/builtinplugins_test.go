package builtinplugins

import (
	"context"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/grpc/codes"
)

func binding() *pluginv1.BindingContext {
	return &pluginv1.BindingContext{
		BindingId: "0190c1b2-0000-7000-8000-000000000001", DerivedPrincipalName: "bnd_abcdefghijklmnop",
		SourceTrustDomain: "prod.internal", SourceSvidRegex: "^spiffe://prod\\.internal/ns/pay/sa/api$",
	}
}

// compile compiles a schema a plugin describes.
func compile(t *testing.T, schema string) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func valid(t *testing.T, s *jsonschema.Schema, doc string) bool {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(v) == nil
}

// TestLookup: the four builtin types of §5.1, and nothing else.
func TestLookup(t *testing.T) {
	for typ, kind := range map[string]pluginv1.PluginKind{
		"svid.v1":              pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER,
		"target-local.v1":      pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER,
		"delegated-dynamic.v1": pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER,
		"none.v1":              pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE,
	} {
		p, ok := Lookup(typ)
		if !ok {
			t.Fatalf("%s: not a builtin", typ)
		}
		if _, err := p.Set(); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
		d, err := p.Control.Describe(context.Background(), &pluginv1.DescribeRequest{})
		if err != nil || d.GetPluginType() != typ || d.GetKind() != kind || d.GetPluginProtocolVersion() != 1 {
			t.Errorf("%s: Describe = (%v, %v)", typ, d, err)
		}
		r, err := p.Control.ConfigureInstances(context.Background(), &pluginv1.ConfigureInstancesRequest{Instances: []*pluginv1.InstanceDescriptor{{Name: "i"}}})
		if err != nil || len(r.GetResolved()) != 0 {
			t.Errorf("%s: builtins hold no SVID: (%v, %v)", typ, r, err)
		}
		if h, err := p.Control.Health(context.Background(), &pluginv1.HealthRequest{Instance: "i"}); err != nil || !h.GetServing() {
			t.Errorf("%s: Health = (%v, %v)", typ, h, err)
		}
	}
	for _, typ := range []string{"oracle.v1", "vault.v1", ""} {
		if _, ok := Lookup(typ); ok {
			t.Errorf("%s: a builtin", typ)
		}
	}
}

// TestInstanceConfig: each builtin's instance_config_schema_json accepts the
// example configuration and nothing unknown (§8.2 rule 8).
func TestInstanceConfig(t *testing.T) {
	for typ, cases := range map[string]map[string]bool{
		"svid.v1":              {`{}`: true, `{"x":1}`: false},
		"delegated-dynamic.v1": {`{}`: true, `{"x":1}`: false},
		"none.v1":              {`{}`: true, `{"x":1}`: false},
		"target-local.v1":      {`{}`: true, `{"password_length":32}`: true, `{"password_length":64}`: true, `{"password_length":31}`: false, `{"password_length":"32"}`: false, `{"x":1}`: false},
	} {
		p, _ := Lookup(typ)
		d, _ := p.Control.Describe(context.Background(), &pluginv1.DescribeRequest{})
		s := compile(t, d.GetInstanceConfigSchemaJson())
		for doc, want := range cases {
			if got := valid(t, s, doc); got != want {
				t.Errorf("%s: %s valid = %t, want %t", typ, doc, got, want)
			}
		}
	}
}

// TestIdentityMarkers: the identity markers create nothing; their artifact
// names the binding's derived principal in their mode, never with a secret,
// and the same request gives the same artifact (ADR-01, §5.8 rules 1-2).
func TestIdentityMarkers(t *testing.T) {
	ctx := context.Background()
	for typ, mode := range map[string]pluginv1.IdentityMode{
		"svid.v1":              pluginv1.IdentityMode_IDENTITY_MODE_SVID,
		"target-local.v1":      pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL,
		"delegated-dynamic.v1": pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC,
	} {
		p, _ := Lookup(typ)
		if _, err := p.Control.ConfigureInstances(ctx, &pluginv1.ConfigureInstancesRequest{Instances: []*pluginv1.InstanceDescriptor{
			{Name: "i", ConfigJson: `{"password_length":40}`},
		}}); err != nil && typ == "target-local.v1" {
			t.Fatal(err)
		}
		d, _ := p.Control.Describe(ctx, &pluginv1.DescribeRequest{})
		if m := d.GetIdentityProvider().GetProducedIdentityMode(); m != mode {
			t.Errorf("%s: produced mode %v", typ, m)
		}
		req := &pluginv1.EnsureIdentityRequest{Instance: "i", Binding: binding()}
		r, err := p.Identity.EnsureIdentity(ctx, req)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		a := r.GetArtifact()
		if a.GetMode() != mode || a.GetPrincipalId() != "bnd_abcdefghijklmnop" || a.GetStaticSecret() != nil {
			t.Errorf("%s: artifact %+v", typ, a)
		}
		again, _ := p.Identity.EnsureIdentity(ctx, req)
		if again.GetArtifact().String() != a.String() {
			t.Errorf("%s: not idempotent", typ)
		}
		if c, err := p.Identity.CleanupIdentity(ctx, &pluginv1.CleanupIdentityRequest{Instance: "i", Binding: binding()}); err != nil || c.GetSkippedNotOwner() {
			t.Errorf("%s: Cleanup = (%v, %v)", typ, c, err)
		}
		_, err = p.Identity.EnsureIdentity(ctx, &pluginv1.EnsureIdentityRequest{Instance: "i", Binding: &pluginv1.BindingContext{}})
		if code, d := pluginsdk.FromError(err); code != codes.InvalidArgument || d.GetCode() != "MISSING_PRINCIPAL_NAME" {
			t.Errorf("%s: no derived name: %v", typ, err)
		}
	}

	// only target-local.v1 has metadata: the length of the password the
	// target generates; the target has the rest in the BindingContext
	// (§5.8 rule 2)
	for _, typ := range []string{"svid.v1", "delegated-dynamic.v1"} {
		p, _ := Lookup(typ)
		if r, _ := p.Identity.EnsureIdentity(ctx, &pluginv1.EnsureIdentityRequest{Instance: "i", Binding: binding()}); len(r.GetArtifact().GetMetadata()) != 0 {
			t.Errorf("%s metadata %v", typ, r.GetArtifact().GetMetadata())
		}
	}
	p, _ := Lookup("target-local.v1")
	if _, err := p.Control.ConfigureInstances(ctx, &pluginv1.ConfigureInstancesRequest{Instances: []*pluginv1.InstanceDescriptor{
		{Name: "i", ConfigJson: `{"password_length":40}`},
	}}); err != nil {
		t.Fatal(err)
	}
	r, _ := p.Identity.EnsureIdentity(ctx, &pluginv1.EnsureIdentityRequest{Instance: "i", Binding: binding()})
	if md := r.GetArtifact().GetMetadata(); md["password_length"] != "40" {
		t.Errorf("target-local.v1 metadata %v", md)
	}
	r, _ = p.Identity.EnsureIdentity(ctx, &pluginv1.EnsureIdentityRequest{Instance: "unconfigured", Binding: binding()})
	if md := r.GetArtifact().GetMetadata(); md["password_length"] != "32" {
		t.Errorf("target-local.v1 default metadata %v", md)
	}
	if _, err := p.Control.ConfigureInstances(ctx, &pluginv1.ConfigureInstancesRequest{Instances: []*pluginv1.InstanceDescriptor{
		{Name: "i", ConfigJson: `{"password_length":8}`},
	}}); err == nil {
		t.Error("a password_length below 32 was accepted")
	}
}

// TestNoneStore: none.v1 stores nothing and only serves the secret storage strategy svid in
// SVID mode (§5.6); the client has nothing to configure, so its output is {}
// and valid against its own client output schema (INV-13).
func TestNoneStore(t *testing.T) {
	ctx := context.Background()
	p, _ := Lookup("none.v1")
	d, _ := p.Control.Describe(ctx, &pluginv1.DescribeRequest{})
	if s := d.GetSecretStore().GetSecretStorageStrategies(); len(s) != 1 || s[0].GetName() != "svid" ||
		len(s[0].GetIdentityModes()) != 1 || s[0].GetIdentityModes()[0] != pluginv1.IdentityMode_IDENTITY_MODE_SVID {
		t.Errorf("strategies %v", s)
	}
	out := compile(t, d.GetSecretStore().GetClientOutputSchemaJson())

	svid := &pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_SVID}
	r, err := p.Store.EnsureSecretStore(ctx, &pluginv1.EnsureSecretStoreRequest{
		Instance: "i", Binding: binding(), SecretPayload: svid, SecretStorageStrategy: "svid",
	})
	if err != nil || string(r.GetFinalizedClientAuthJson()) != "{}" || !valid(t, out, "{}") || len(r.GetDeclaredEndpoints()) != 0 {
		t.Fatalf("EnsureSecretStore = (%v, %v)", r, err)
	}
	if valid(t, out, `{"mode":"SVID"}`) {
		t.Error("the output schema accepts a property")
	}
	for name, req := range map[string]*pluginv1.EnsureSecretStoreRequest{
		"no payload":     {SecretStorageStrategy: "svid"},
		"target-local":   {SecretPayload: &pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL}, SecretStorageStrategy: "svid"},
		"other strategy": {SecretPayload: svid, SecretStorageStrategy: "vault-static"},
		"no strategy":    {SecretPayload: svid},
		"a secret": {SecretPayload: &pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_SVID,
			Payload: &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: &pluginv1.StaticSecret{Password: "x"}}}, SecretStorageStrategy: "svid"},
	} {
		req.Instance, req.Binding = "i", binding()
		_, err := p.Store.EnsureSecretStore(ctx, req)
		if code, d := pluginsdk.FromError(err); code != codes.FailedPrecondition || d.GetCode() != "INCOMPATIBLE_IDENTITY_MODE" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if c, err := p.Store.CleanupSecretStore(ctx, &pluginv1.CleanupSecretStoreRequest{Instance: "i", Binding: binding()}); err != nil || c.GetSkippedNotOwner() {
		t.Errorf("Cleanup = (%v, %v)", c, err)
	}
}
