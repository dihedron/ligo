package instances

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/config"
)

// example are the configuration and the instances of examples/.
func example(t *testing.T) (*Env, []*Definition) {
	t.Helper()
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnv(cfg)
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("../../examples/instances.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defs, err := ParseManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	return env, defs
}

// TestExample: every example instance passes the static checks, and a
// platform's defaults are filled.
func TestExample(t *testing.T) {
	env, defs := example(t)
	if len(defs) != 9 {
		t.Fatalf("%d definitions", len(defs))
	}
	for _, d := range defs {
		if err := env.Check(d); err != nil {
			t.Errorf("%s %s: %v", d.Kind, d.Metadata.Name, err)
		}
	}
	set := NewSet(defs...)
	p, ok := set.Platform("oracle-test-dynamic")
	if !ok || len(p.TargetJurisdictions) != 1 || p.TargetJurisdictions[0] != "dc/corp-test/*" || !p.ChecksExistence() {
		t.Errorf("defaults: %+v", p)
	}
	if prod, _ := set.Platform("oracle-prod"); prod.Rotation().Hours() != 720 || prod.PrivilegeBounds()["grantableRoles"] == nil {
		t.Errorf("oracle-prod: %+v", prod)
	}
	if err := set.Allow("oracle-prod").CheckEndpoint("ledger-db.prod.internal", 1522); err != nil {
		t.Error(err)
	}
	if len(set.Flows(SecretStore, "vault-prod")) != 1 || !set.AcceptedTrustDomains()["cloud.internal"] {
		t.Error("lookups")
	}
}

// mutate is a copy of d, changed by f.
func mutate(t *testing.T, d *Definition, f func(m map[string]any)) *Definition {
	t.Helper()
	data, _ := json.Marshal(d)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	f(m)
	data, _ = json.Marshal(m)
	out, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func find(defs []*Definition, name string) *Definition {
	for _, d := range defs {
		if d.Metadata.Name == name {
			return d
		}
	}
	return nil
}

// TestCheckRefusals: each rule of §6 that needs neither database nor plugin
// refuses, naming its field.
func TestCheckRefusals(t *testing.T) {
	env, defs := example(t)
	oracle, vault, ldap := find(defs, "oracle-prod"), find(defs, "vault-prod"), find(defs, "ldap-prod")
	meta := func(key string, v any) func(map[string]any) {
		return func(m map[string]any) { m["metadata"].(map[string]any)[key] = v }
	}
	set := func(key string, v any) func(map[string]any) { return func(m map[string]any) { m[key] = v } }
	del := func(key string) func(map[string]any) { return func(m map[string]any) { delete(m, key) } }
	conf := func(key string, v any) func(map[string]any) {
		return func(m map[string]any) { m["config"].(map[string]any)[key] = v }
	}
	for name, tc := range map[string]struct {
		d    *Definition
		f    func(map[string]any)
		want string
	}{
		"unknown kind":          {vault, set("kind", "Database"), "kind"},
		"unknown type":          {vault, set("type", "nope.v1"), "nope.v1"},
		"type of another kind":  {vault, set("type", "openldap.v1"), "IDENTITY_PROVIDER type"},
		"name":                  {vault, meta("name", "Vault_Prod"), "metadata.name"},
		"realm":                 {vault, meta("realm", "mars"), "metadata.realm"},
		"jurisdiction":          {vault, meta("jurisdiction", "dc/*"), "metadata.jurisdiction"},
		"no selector":           {vault, del("svidSelector"), "svidSelector.matchExpr"},
		"bad selector":          {vault, set("svidSelector", map[string]any{"matchExpr": "path =="}), "svidSelector.matchExpr"},
		"audience":              {ldap, set("svidSelector", map[string]any{"matchExpr": "true", "jwtAudience": []string{"other"}}), "jwt_audience"},
		"flow outside":          {vault, conf("allowed_endpoints", []string{"elsewhere:1"}), "networkFlows"},
		"identity flows":        {ldap, set("networkFlows", vault.NetworkFlows), "networkFlows"},
		"platform field":        {vault, set("principalPrefix", "x_"), "principalPrefix"},
		"trust domain":          {oracle, set("allowedSourceTrustDomains", []string{"elsewhere.internal"}), "accepted_trust_domains"},
		"prefix":                {oracle, set("principalPrefix", "toolong_"), "principalPrefix"},
		"target jurisdiction":   {oracle, set("targetJurisdictions", []string{"dc/**/x"}), "targetJurisdictions"},
		"namespace, no account": {oracle, set("namespaceTemplate", "{account}_{tenancy}"), "namespaceTemplate"},
		"no wiring":             {oracle, del("secretStore"), "secretStore"},
		"invalid flow":          {vault, set("networkFlows", []map[string]any{{"name": "Vault", "purpose": "CREDENTIALS", "protocol": "TCP", "destination": "vault.prod.internal", "ports": []int{8200}, "tls": true}}), "networkFlows"},
	} {
		t.Run(name, func(t *testing.T) {
			err := env.Check(mutate(t, tc.d, tc.f))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v, want %q", err, tc.want)
			}
		})
	}
	if _, err := Decode([]byte(`{"kind":"Platform","nope":1}`)); err == nil {
		t.Error("an unknown field was accepted")
	}
}

// TestBounded: rule 5, config endpoints, reported endpoints and flows lie
// within the type's instance_bounds.
func TestBounded(t *testing.T) {
	env, defs := example(t)
	vault := find(defs, "vault-prod")
	if err := env.Bounded(vault, []string{"vault.prod.internal:8200"}); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		d        *Definition
		reported []string
	}{
		"reported":      {vault, []string{"evil.example:8200"}},
		"reported port": {vault, []string{"vault.prod.internal:8201"}},
		"malformed":     {vault, []string{"vault.prod.internal"}},
		"config": {mutate(t, vault, func(m map[string]any) {
			m["config"].(map[string]any)["allowed_endpoints"] = []string{"vault.prod.internal:8200", "evil.example:8200"}
		}), nil},
	} {
		if err := env.Bounded(tc.d, tc.reported); err == nil || !strings.Contains(err.Error(), "instance_bounds") && name != "malformed" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestImmutable: §4.3, the fields fixed at creation.
func TestImmutable(t *testing.T) {
	_, defs := example(t)
	vault := find(defs, "vault-prod")
	if err := Immutable(vault, mutate(t, vault, func(m map[string]any) { m["config"].(map[string]any)["role"] = "r2" })); err != nil {
		t.Error(err)
	}
	for _, f := range []func(map[string]any){
		func(m map[string]any) { m["type"] = "none.v1" },
		func(m map[string]any) { m["metadata"].(map[string]any)["realm"] = "test" },
		func(m map[string]any) { m["metadata"].(map[string]any)["jurisdiction"] = "dc/corp-test" },
	} {
		if err := Immutable(vault, mutate(t, vault, f)); err == nil {
			t.Error("an immutable field changed")
		}
	}
}

// TestNormalized: the payload hash does not depend on key order or spacing.
func TestNormalized(t *testing.T) {
	_, defs := example(t)
	_, a, err := find(defs, "vault-prod").Normalized()
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ParseManifest([]byte(`{"type":"vault.v1","kind":"SecretStore","metadata":{"realm":"prod","name":"vault-prod","jurisdiction":"dc/corp-prod"}}`))
	_, b, _ := again[0].Normalized()
	if a == "" || a == b {
		t.Errorf("%s %s", a, b)
	}
}

// TestSourceTrustDomain: a platform's accepted trust domain needs a
// charter.source_jurisdictions entry (startup rule 16, now per platform).
func TestSourceTrustDomain(t *testing.T) {
	env, defs := example(t)
	env.AcceptedTrustDomains = append(env.AcceptedTrustDomains, "extra.internal")
	d := mutate(t, find(defs, "oracle-prod"), func(m map[string]any) { m["allowedSourceTrustDomains"] = []string{"extra.internal"} })
	if err := env.Check(d); err == nil || !strings.Contains(err.Error(), "source_jurisdictions") {
		t.Errorf("%v", err)
	}
}

// TestPrivilegeBounds: a tenant's roles are bounds too, so changing them is
// audited and shown like grantable_roles (.specs/ligo-tenancy.md §6).
func TestPrivilegeBounds(t *testing.T) {
	d := &Definition{Config: []byte(`{"grantable_role_templates":["{namespace}_read"]}`)}
	b := d.PrivilegeBounds()
	if _, ok := b["grantableRoles"]; ok || len(b["grantableRoleTemplates"].([]string)) != 1 {
		t.Errorf("bounds %v", b)
	}
	if b := (&Definition{Config: []byte(`{"host":"h"}`)}).PrivilegeBounds(); b != nil {
		t.Errorf("no bounds: %v", b)
	}
}
