package config

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// example returns examples/server.yaml (the §8.1 reference) with its
// placeholder checksums replaced.
func example(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return regexp.MustCompile(`<64-hex-sha256-of-[a-z-]+>`).ReplaceAllString(string(data), strings.Repeat("ab", 32))
}

var env = map[string]string{"LIGO_WEBHOOK_ONCALL_SECRET": "x", "LIGO_WEBHOOK_DBA_SECRET": "y"}

func lookupEnv(k string) (string, bool) { v, ok := env[k]; return v, ok }

func parse(t *testing.T, doc string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestExample checks that the §8.1 reference parses and passes every static
// rule.
func TestExample(t *testing.T) {
	cfg := parse(t, example(t))
	if err := Validate(cfg, Options{LookupEnv: lookupEnv}); err != nil {
		t.Fatal(err)
	}
	p := cfg.PlatformProviders[0].Platforms[0]
	if p.Name != "oracle-prod" || p.PrincipalPrefix != "svc_" || p.SecretStore.SecretStorageStrategy != "vault-static" || p.RotationInterval != 720*time.Hour || len(p.NetworkFlows) != 1 || p.NetworkFlows[0].ServerName != "ora-scan.prod.internal" {
		t.Errorf("platform not decoded: %+v", p)
	}
	if got := cfg.PlatformProviders[0].Platforms[1].TargetScopes; len(got) != 1 || got[0] != "dc/corp-test/*" {
		t.Errorf("default target_scopes = %v", got)
	}
	if !*cfg.Authorization.Approval.RequireDistinctApproversAcrossScopes || cfg.RegexPolicy.NarrowingStateLimit != 20000 {
		t.Error("defaults not applied")
	}
	if cfg.Governance.NamePrefixes[0].Prefix != "{2}-{3}-" || cfg.SecretSealing.VaultTransit.KeyName != "ligo-interstage" {
		t.Error("nested types not decoded")
	}
}

func TestStrict(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown top-level key": example(t) + "\nbogus: 1\n",
		"unknown nested key":    strings.Replace(example(t), "  max_length: 512", "  max_length: 512\n  max_lenght: 1", 1),
		"two documents":         example(t) + "\n---\nservice: {}\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestRules breaks the example once per case and checks that validation
// fails on the expected rule.
func TestRules(t *testing.T) {
	for _, v := range []struct {
		name, old, new string
		rule           int
		also           []int // rules that fail in consequence
	}{
		{"duplicate zone", "  - name: test\n    trust_domain: test.internal", "  - name: prod\n    trust_domain: test.internal", 1, []int{2, 12}},
		{"duplicate instance", `name: "vault-test"`, `name: "vault-prod"`, 1, []int{2}},
		{"unknown zone", `      - { name: "no-store-prod", zone: prod`, `      - { name: "no-store-prod", zone: nowhere`, 2, nil},
		{"wiring across zones", `secret_store: { type: "vault.v1", instance: "vault-prod", secret_storage_strategy`, `secret_store: { type: "vault.v1", instance: "vault-test", secret_storage_strategy`, 2, nil},
		{"missing instance", `identity_provider: { type: "openldap.v1", instance: "ldap-prod" }`, `identity_provider: { type: "openldap.v1", instance: "ldap-nope" }`, 2, nil},
		{"bootstrap audience", `role: "ligo-plugin-ldap-prod"
            jwt_audience: "https://vault.prod.internal"`, `role: "ligo-plugin-ldap-prod"
            jwt_audience: "https://other"`, 5, nil},
		{"trust domain not accepted", "allowed_source_trust_domains: [test.internal]", "allowed_source_trust_domains: [test.internal, other.internal]", 6, []int{16}},
		{"bad principal prefix", `principal_prefix: "svc_"`, `principal_prefix: "svc-"`, 6, nil},
		{"bad sha256", `binary: "store-vault"
    sha256: "` + strings.Repeat("ab", 32) + `"`, `binary: "store-vault"
    sha256: "ABC"`, 7, nil},
		{"local-kek without --insecure-dev", "provider: vault-transit", "provider: local-kek", 9, nil},
		{"zone domain also federated", "{ trust_domain: cloud.internal, via_zone: prod }", "{ trust_domain: prod.internal, via_zone: prod }", 12, nil},
		{"unknown via_zone", "via_zone: prod }", "via_zone: nowhere }", 12, nil},
		{"AC-29: trusted_automation on an LDAP group", `- spiffe_id: "spiffe://prod.internal/ns/automation-prod/sa/awx-runner-db-team"`, `- ldap_group_dn: "cn=awx,ou=groups,dc=corp,dc=internal"`, 13, nil},
		{"unanchored reference", `approval_reference_pattern: '^CHG[0-9]{7}$'`, `approval_reference_pattern: 'CHG[0-9]{7}'`, 13, nil},
		{"unknown automation platform", `platforms: ["oracle-prod"]`, `platforms: ["oracle-nope"]`, 13, nil},
		{"break_glass on a SPIFFE ID", `{ ldap_group_dn: "cn=ligo-breakglass-prod,ou=groups,dc=corp,dc=internal",  role: break_glass`, `{ spiffe_id: "spiffe://prod.internal/x",  role: break_glass`, 14, nil},
		{"break_glass scope without policy", `role: break_glass, scopes: ["dc/corp-prod/*"]`, `role: break_glass, scopes: ["dc/corp-prod"]`, 14, nil},
		{"ttl above 24h", "default_ttl: 4h, max_ttl: 8h", "default_ttl: 4h, max_ttl: 25h", 14, nil},
		{"short justification", "min_justification_length: 20", "min_justification_length: 10", 14, nil},
		{"http webhook", `url: "https://oncall.corp.internal/hooks/ligo"`, `url: "http://oncall.corp.internal/hooks/ligo"`, 14, nil},
		{"unset webhook secret", "LIGO_WEBHOOK_DBA_SECRET", "LIGO_WEBHOOK_UNSET", 14, nil},
		{"bad scope pattern", `required_scopes: ["dc/corp-prod/*", "cloud/fin-01/*"]`, `required_scopes: ["dc/*/x"]`, 16, nil},
		{"platform scope is a pattern", `scope: "dc/corp-prod"            #`, `scope: "dc/corp-prod/*"            #`, 16, nil},
		{"source scope missing", "    - { trust_domain: test.internal, mode: static, scope: \"dc/corp-test\" }\n", "", 16, nil},
		{"bad path_template", `path_regex: '^/acct/([a-z0-9-]+)/tenant/([a-z0-9-]+)/'`, `path_regex: '^/acct/(.+)/'`, 16, nil},
		{"reserved rule name", "name: no-test-to-prod", "name: default", 16, nil},
		{"party on a deny rule", "        action: deny\n", "        action: deny\n        additional_approvals: [ { name: x, scope: \"a\" } ]\n", 16, nil},
		{"unknown name prefix resource", "resources: [source, target, binding]", "resources: [source, platform]", 16, nil},
		{"flow outside allowed_endpoints", `destination: "ora-scan.prod.internal", ports: [1521]`, `destination: "ora-scan.prod.internal", ports: [1600]`, 19, nil},
		{"invalid flow", `- { name: listener, purpose: DATA`, `- { name: Listener, purpose: DATA`, 19, nil},
		{"no workload_advertise", `    destination: "ligo.prod.internal"`, `    destination: ""`, 19, nil},
	} {
		doc := example(t)
		if !strings.Contains(doc, v.old) {
			t.Fatalf("%s: %q not in the example", v.name, v.old)
		}
		err := Validate(parse(t, strings.Replace(doc, v.old, v.new, 1)), Options{LookupEnv: lookupEnv})
		if err == nil {
			t.Errorf("%s: accepted, want rule %d", v.name, v.rule)
			continue
		}
		found := false
		for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
			l := e.Error()
			rule, _, _ := strings.Cut(strings.TrimPrefix(l, "rule "), ":")
			n, _ := strconv.Atoi(rule)
			found = found || n == v.rule
			if n != v.rule && !slices.Contains(v.also, n) {
				t.Errorf("%s: unexpected failure %q (want rule %d)", v.name, l, v.rule)
			}
		}
		if !found {
			t.Errorf("%s: rule %d did not fail: %v", v.name, v.rule, err)
		}
	}
}

func TestInsecureDev(t *testing.T) {
	doc := strings.Replace(example(t), "provider: vault-transit", "provider: local-kek", 1)
	if err := Validate(parse(t, doc), Options{InsecureDev: true, LookupEnv: lookupEnv}); err == nil || !strings.Contains(err.Error(), "local_kek_file") {
		t.Errorf("local-kek without local_kek_file: %v", err)
	}
	doc = strings.Replace(doc, "  # local_kek_file:", "  local_kek_file:", 1)
	if err := Validate(parse(t, doc), Options{InsecureDev: true, LookupEnv: lookupEnv}); err != nil {
		t.Error(err)
	}
}

// TestPolicy checks the governance policy built from the §8.1 example.
func TestPolicy(t *testing.T) {
	p := parse(t, example(t)).Policy()
	if d := p.Evaluate("dc/corp-test", "dc/corp-prod/ledger"); d.Allowed || d.Rule != "no-test-to-prod" {
		t.Errorf("AC-51: %+v", d)
	}
	if len(p.Platforms) != 2 || !p.RequireDistinctApprovers || len(p.BreakGlassPolicies) != 2 || len(p.SHA256()) != 64 {
		t.Errorf("policy: %+v", p)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/server.yaml"
	if err := os.WriteFile(path, []byte(example(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, sum, err := Load(path)
	if err != nil || cfg == nil || len(sum) != 64 {
		t.Fatalf("Load = (%v, %q, %v)", cfg, sum, err)
	}
	if _, _, err := Load(dir + "/missing.yaml"); err == nil {
		t.Error("missing file accepted")
	}
	if err := os.WriteFile(path, []byte("zones: {"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Error("invalid YAML accepted")
	}
}

// TestDefaults checks the defaults of an almost empty file.
func TestDefaults(t *testing.T) {
	cfg := parse(t, "platform_providers: [ { type: t, platforms: [ { name: p, scope: dc/x } ] } ]\n")
	if !*cfg.Authorization.Approval.RequireDistinctApproversAcrossScopes || cfg.Governance.Interconnects.DefaultCrossScope != "deny" ||
		cfg.Bindings.MaxExpiry != 8760*time.Hour || cfg.Bindings.ExpiryWarning != 168*time.Hour ||
		cfg.PlatformProviders[0].Platforms[0].TargetScopes[0] != "dc/x/*" {
		t.Errorf("defaults: %+v", cfg)
	}
	if err := Validate(cfg, Options{}); err == nil {
		t.Error("an almost empty configuration passed validation")
	}
}

// TestPluginRules covers the binary and selector checks of builtin and
// external plugins.
func TestPluginRules(t *testing.T) {
	for _, v := range []struct{ name, old, new string }{
		{"builtin with a binary", `  - type: "none.v1"
    builtin: true`, `  - type: "none.v1"
    builtin: true
    binary: "x"`},
		{"binary path", `binary: "store-vault"`, `binary: "../store-vault"`},
		{"no selector", `          match_expr: 'path == "/ligo/plugin/store-vault" && hint == "vault-prod"'`, `          match_expr: ''`},
		{"selector not boolean", `          match_expr: 'path == "/ligo/plugin/store-vault" && hint == "vault-prod"'`, `          match_expr: 'hint'`},
		{"selector unknown field", `          match_expr: 'path == "/ligo/plugin/store-vault" && hint == "vault-prod"'`, `          match_expr: 'spiffeID == "x"'`},
		{"config not a mapping", `          host: "ora-scan.prod.internal"`, `          allowed_endpoints: 7
          host: "ora-scan.prod.internal"`},
		{"identity provider flows", `          kv_path: "kv/data/ligo/bootstrap/ldap-prod"`, `          kv_path: "kv/data/ligo/bootstrap/ldap-prod"
        network_flows: [ { name: x, purpose: DATA, protocol: TCP, destination: "h", ports: [1], tls: false } ]`},
		{"bad allowlist", `allowed_endpoints: ["vault.test.internal:8200"]`, `allowed_endpoints: ["vault.test.internal:0"]`},
		{"bad spiffe_id", `spiffe_id: "spiffe://prod.internal/ns/ci/sa/ligo-deployer"`, `spiffe_id: "http://x"`},
		{"unknown role", `role: viewer,`, `role: superuser,`},
		{"two principals", `- { ldap_group_dn: "cn=ligo-viewers,ou=groups,dc=corp,dc=internal",`, `- { spiffe_id: "spiffe://prod.internal/v", ldap_group_dn: "cn=ligo-viewers,ou=groups,dc=corp,dc=internal",`},
		{"platforms on an operator", `role: operator,    scopes: ["dc/corp-test"] }`, `role: operator,    scopes: ["dc/corp-test"], platforms: ["oracle-prod"] }`},
		{"no scopes", `role: viewer,      scopes: ["*"]`, `role: viewer,      scopes: []`},
		{"bad incident pattern", `incident_reference_pattern: '^INC[0-9]{7}$'`, `incident_reference_pattern: 'INC['`},
		{"bad sealing provider", "provider: vault-transit", "provider: kms"},
		{"bad default_cross_scope", "default_cross_scope: deny", "default_cross_scope: maybe"},
		{"bad action", "        action: deny\n", "        action: drop\n"},
		{"duplicate party", `- { name: security, scope: "sec/infosec" }`, `- { name: security, scope: "sec/infosec" }
          - { name: security, scope: "sec/other" }`},
		{"unknown core zone", "core_identity:                           # ligo's own SVID (serving TLS, Vault Transit)\n  zone: prod", "core_identity:\n  zone: nowhere"},
		{"bad zone trust domain", "trust_domain: test.internal\n    spiffe_workload_socket", "trust_domain: Test..Internal\n    spiffe_workload_socket"},
		{"source scope for an unused trust domain", `    - { trust_domain: prod.internal, mode: static, scope: "dc/corp-prod" }`, `    - { trust_domain: prod.internal, mode: static, scope: "dc/corp-prod" }
    - { trust_domain: other.internal, mode: static, scope: "dc/other" }`},
		{"bad source scope mode", `mode: static, scope: "dc/corp-test"`, `mode: dynamic, scope: "dc/corp-test"`},
	} {
		doc := example(t)
		if !strings.Contains(doc, v.old) {
			t.Fatalf("%s: %q not in the example", v.name, v.old)
		}
		cfg, err := Parse([]byte(strings.Replace(doc, v.old, v.new, 1)))
		if err != nil {
			t.Logf("%s: refused by the parser: %v", v.name, err)
			continue
		}
		if err := Validate(cfg, Options{LookupEnv: lookupEnv}); err == nil {
			t.Errorf("%s: accepted", v.name)
		}
	}
}
