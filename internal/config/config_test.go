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

var env = map[string]string{"LIGO_INSTANCE_ID": "ligo-1", "LIGO_WEBHOOK_ONCALL_SECRET": "x", "LIGO_WEBHOOK_DBA_SECRET": "y"}

func lookupEnv(k string) (string, bool) { v, ok := env[k]; return v, ok }

// TestInstanceID: PostgreSQL truncates application_name at 63 bytes, so a
// longer ID, or one it would rewrite, would look dead (§10.2).
func TestInstanceID(t *testing.T) {
	cfg := parse(t, example(t))
	for id, ok := range map[string]bool{"ligo-0": true, "ligo1.dc1_a": true, strings.Repeat("a", 58): true,
		"": false, strings.Repeat("a", 59): false, "ligo 1": false, "ligo/1": false, "lìgo": false} {
		err := Validate(cfg, Options{LookupEnv: func(k string) (string, bool) {
			if k == "LIGO_INSTANCE_ID" {
				return id, true
			}
			return lookupEnv(k)
		}})
		if got := err == nil || !strings.Contains(err.Error(), "instance ID"); got != ok {
			t.Errorf("instance ID %q: %v", id, err)
		}
	}
	unset := func(k string) (string, bool) {
		if k == "LIGO_INSTANCE_ID" {
			return "", false
		}
		return lookupEnv(k)
	}
	if err := Validate(cfg, Options{LookupEnv: unset}); err == nil || !strings.Contains(err.Error(), "instance ID") {
		t.Errorf("no instance ID: %v", err)
	}
}

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
	if v := cfg.SecretStores[1]; v.Type != "vault.v1" || v.InstanceBounds == nil || len(v.InstanceBounds.AllowedEndpoints) != 2 {
		t.Errorf("plugin type not decoded: %+v", v)
	}
	if !*cfg.Authorization.Approval.RequireDistinctApproversAcrossJurisdictions || cfg.RegexPolicy.NarrowingStateLimit != 20000 {
		t.Error("defaults not applied")
	}
	if cfg.Charter.NamePrefixes[0].Prefix != "{2}-{3}-" || cfg.SecretSealing.VaultTransit.KeyName != "ligo-interstage" {
		t.Error("nested types not decoded")
	}
}

func TestStrict(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown top-level key":             example(t) + "\nbogus: 1\n",
		"unknown nested key":                strings.Replace(example(t), "  max_length: 512", "  max_length: 512\n  max_lenght: 1", 1),
		"two documents":                     example(t) + "\n---\nservice: {}\n",
		"zones, renamed to realms in 4.0.3": strings.Replace(example(t), "\nrealms:", "\nzones:", 1),
		"source_scopes, renamed to source_jurisdictions in 4.0.4": strings.Replace(example(t), "  source_jurisdictions:", "  source_scopes:", 1),
		"governance, renamed to charter in 4.0.5":                 strings.Replace(example(t), "\ncharter:", "\ngovernance:", 1),
		"instances, moved to the database in 4.1.0":               strings.Replace(example(t), `  - { type: "none.v1", builtin: true }`, `  - { type: "none.v1", builtin: true, instances: [] }`, 1),
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
		{"duplicate realm", "  - name: test\n    trust_domain: test.internal", "  - name: prod\n    trust_domain: test.internal", 1, []int{2, 12}},
		{"type in two sections", `  - type: "oracle.v1"`, `  - type: "openldap.v1"`, 1, nil},
		{"no instance_bounds", `    instance_bounds:
      allowed_endpoints: ["vault.prod.internal:8200", "vault.test.internal:8200"]`, ``, 1, nil},
		{"bad sha256", `binary: "ligo-plugin-vault"
    sha256: "` + strings.Repeat("ab", 32) + `"`, `binary: "ligo-plugin-vault"
    sha256: "ABC"`, 7, nil},
		{"local-kek without --insecure-dev", "provider: vault-transit", "provider: local-kek", 9, nil},
		{"tracing CA without TLS", "    insecure: false                       # true only for a collector without TLS", "    insecure: true\n    ca_cert_file: /etc/ligo/ca.crt", 9, nil},
		{"realm domain also federated", "{ trust_domain: cloud.internal, via_realm: prod }", "{ trust_domain: prod.internal, via_realm: prod }", 12, nil},
		{"unknown via_realm", "via_realm: prod }", "via_realm: nowhere }", 12, nil},
		{"no auth mode", "auth_modes: [x509_svid, jwt_svid]", "auth_modes: []", 12, nil},
		{"unknown auth mode", "auth_modes: [x509_svid, jwt_svid]", "auth_modes: [x509_svid, basic]", 12, nil},
		{"jwt_svid without audience", `expected_jwt_audience: "spiffe://prod.internal/ns/sys/sa/ligo"`, `expected_jwt_audience: ""`, 12, nil},
		{"AC-29: trusted_automation on an LDAP group", `- spiffe_id: "spiffe://prod.internal/ns/automation-prod/sa/awx-runner-db-team"`, `- ldap_group_dn: "cn=awx,ou=groups,dc=corp,dc=internal"`, 13, nil},
		{"unanchored reference", `approval_reference_pattern: '^CHG[0-9]{7}$'`, `approval_reference_pattern: 'CHG[0-9]{7}'`, 13, nil},
		{"break_glass on a SPIFFE ID", `{ ldap_group_dn: "cn=ligo-breakglass-prod,ou=groups,dc=corp,dc=internal",  role: break_glass`, `{ spiffe_id: "spiffe://prod.internal/x",  role: break_glass`, 14, nil},
		{"break_glass jurisdiction without policy", `role: break_glass, jurisdictions: ["dc/corp-prod/*"]`, `role: break_glass, jurisdictions: ["dc/corp-prod"]`, 14, nil},
		{"ttl above 24h", "default_ttl: 4h, max_ttl: 8h", "default_ttl: 4h, max_ttl: 25h", 14, nil},
		{"short justification", "min_justification_length: 20", "min_justification_length: 10", 14, nil},
		{"http webhook", `url: "https://oncall.corp.internal/hooks/ligo"`, `url: "http://oncall.corp.internal/hooks/ligo"`, 14, nil},
		{"unset webhook secret", "LIGO_WEBHOOK_DBA_SECRET", "LIGO_WEBHOOK_UNSET", 14, nil},
		{"change request retention below 24h", "  change_requests:\n    retention: 0s", "  change_requests:\n    retention: 2h", 9, nil},
		{"audit retention below 24h", "  audit:\n    retention: 0s", "  audit:\n    retention: 23h", 9, nil},
		{"negative delivered retention", "  delivered_retention: 24h", "  delivered_retention: -1h", 14, nil},
		{"negative abandoned retention", "  abandoned_retention: 720h", "  abandoned_retention: -1h", 14, nil},
		{"bad jurisdiction pattern", `required_jurisdictions: ["dc/corp-prod/*", "cloud/fin-01/*"]`, `required_jurisdictions: ["dc/*/x"]`, 16, nil},
		{"bad path_template", `path_regex: '^/acct/([a-z0-9-]+)/tenant/([a-z0-9-]+)/'`, `path_regex: '^/acct/(.+)/'`, 16, nil},
		{"reserved rule name", "name: no-test-to-prod", "name: default", 16, nil},
		{"party on a deny rule", "        action: deny\n", "        action: deny\n        additional_approvals: [ { name: x, jurisdiction: \"a\" } ]\n", 16, nil},
		{"unknown name prefix resource", "resources: [source, target, binding]", "resources: [source, platform]", 16, nil},
		{"unknown default mode", "default_mode: system", "default_mode: sepia", 15, nil},
		{"unknown color token", "light: { primary: ", "light: { accent: ", 15, nil},
		{"not a hex color", `primary: "#1f4e8c"`, `primary: "blue"`, 15, nil},
		{"unknown color mode", "dark:  { primary:", "dim:  { primary:", 15, nil},
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

// TestPolicy checks the charter built from the §8.1 example.
func TestPolicy(t *testing.T) {
	p := parse(t, example(t)).Policy()
	if d := p.Evaluate("dc/corp-test", "dc/corp-prod/ledger"); d.Allowed || d.Rule != "no-test-to-prod" {
		t.Errorf("AC-51: %+v", d)
	}
	if !p.RequireDistinctApprovers || len(p.BreakGlassPolicies) != 3 || len(p.SHA256()) != 64 {
		t.Errorf("policy: %+v", p)
	}
	if got := p.PartiesWithoutBreakGlass(); len(got) != 0 {
		t.Errorf("the example leaves parties without break-glass: %v", got)
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
	if err := os.WriteFile(path, []byte("realms: {"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Error("invalid YAML accepted")
	}
}

// TestDefaults checks the defaults of an almost empty file.
func TestDefaults(t *testing.T) {
	cfg := parse(t, "platform_providers: [ { type: t } ]\n")
	if !*cfg.Authorization.Approval.RequireDistinctApproversAcrossJurisdictions || cfg.Charter.Interconnects.DefaultCrossJurisdiction != "deny" ||
		cfg.Bindings.MaxExpiry != 8760*time.Hour || cfg.Bindings.ExpiryWarning != 168*time.Hour ||
		cfg.Plugins.RPCTimeout != time.Minute ||
		cfg.Plugins.MaxConcurrentRPCsPerInstance != 4 || cfg.Service.StartupTimeout != time.Minute ||
		*cfg.Notifications.DeliveredRetention != 24*time.Hour || *cfg.Notifications.AbandonedRetention != 720*time.Hour {
		t.Errorf("defaults: %+v", cfg)
	}
	// 0 is kept: delivered rows go in the pass that delivered them
	if cfg := parse(t, "notifications: { delivered_retention: 0s }\n"); *cfg.Notifications.DeliveredRetention != 0 {
		t.Errorf("delivered_retention 0 became %v", *cfg.Notifications.DeliveredRetention)
	}
	if err := Validate(cfg, Options{}); err == nil {
		t.Error("an almost empty configuration passed validation")
	}
}

// TestPluginRules covers the binary and selector checks of builtin and
// external plugins.
func TestPluginRules(t *testing.T) {
	for _, v := range []struct{ name, old, new string }{
		{"builtin with a binary", `  - { type: "none.v1", builtin: true }`, `  - { type: "none.v1", builtin: true, binary: "x" }`},
		{"binary path", `binary: "ligo-plugin-vault"`, `binary: "../ligo-plugin-vault"`},
		{"bad spiffe_id", `spiffe_id: "spiffe://prod.internal/ns/ci/sa/ligo-deployer"`, `spiffe_id: "http://x"`},
		{"unknown role", `role: viewer,`, `role: superuser,`},
		{"two principals", `- { ldap_group_dn: "cn=ligo-viewers,ou=groups,dc=corp,dc=internal",`, `- { spiffe_id: "spiffe://prod.internal/v", ldap_group_dn: "cn=ligo-viewers,ou=groups,dc=corp,dc=internal",`},
		{"platforms on an operator", `role: operator,    jurisdictions: ["dc/corp-test"] }`, `role: operator,    jurisdictions: ["dc/corp-test"], platforms: ["oracle-prod"] }`},
		{"no jurisdictions", `role: viewer,      jurisdictions: ["*"]`, `role: viewer,      jurisdictions: []`},
		{"bad incident pattern", `incident_reference_pattern: '^INC[0-9]{7}$'`, `incident_reference_pattern: 'INC['`},
		{"bad sealing provider", "provider: vault-transit", "provider: kms"},
		{"startup_timeout too short", `  application_version: "4.0.1"`, "  startup_timeout: 1s\n  application_version: \"4.0.1\""},
		{"max_tracked_keys too few", "max_tracked_keys: 1000000", "max_tracked_keys: 9999"},
		{"max_tracked_keys too many", "max_tracked_keys: 1000000", "max_tracked_keys: 10000001"},
		{"max_conns too many", "max_conns: 25", "max_conns: 1001"},
		{"transit audience not the core identity's", `    jwt_audience: "https://vault.prod.internal"
    mount: "transit"`, `    jwt_audience: "https://vault.other.internal"
    mount: "transit"`},
		{"app_statement_timeout too long", "app_statement_timeout: 5s", "app_statement_timeout: 10m"},
		{"reader_statement_timeout too short", "reader_statement_timeout: 500ms", "reader_statement_timeout: 10ms"},
		{"startup_timeout too long", `  application_version: "4.0.1"`, "  startup_timeout: 1h\n  application_version: \"4.0.1\""},
		{"bad default_cross_jurisdiction", "default_cross_jurisdiction: deny", "default_cross_jurisdiction: maybe"},
		{"bad action", "        action: deny\n", "        action: drop\n"},
		{"duplicate party", `- { name: security, jurisdiction: "sec/infosec" }`, `- { name: security, jurisdiction: "sec/infosec" }
          - { name: security, jurisdiction: "sec/other" }`},
		{"unknown core realm", "core_identity:                           # ligo's own SVID (serving TLS, Vault Transit)\n  realm: prod", "core_identity:\n  realm: nowhere"},
		{"bad realm trust domain", "trust_domain: test.internal\n    spiffe_workload_socket", "trust_domain: Test..Internal\n    spiffe_workload_socket"},
		{"bad instance_bounds", `allowed_endpoints: ["openldap.prod.internal:636", "vault.prod.internal:8200"]`, `allowed_endpoints: ["openldap.prod.internal:0"]`},
		{"bad source jurisdiction mode", `mode: static, jurisdiction: "dc/corp-test"`, `mode: dynamic, jurisdiction: "dc/corp-test"`},
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

func TestAccounts(t *testing.T) {
	const block = `charter:
  accounts:
    jurisdiction: "cloud/{account}"
    source_jurisdiction: "cloud/{account}/app/{project}"
    target_jurisdiction: "cloud/{account}/data/{tenancy}"
    ldap_groups:
      search_base: "ou=accounts,dc=corp,dc=internal"
      roles:
        - { group_dn: "cn=approvers,ou={account},ou=accounts,dc=corp,dc=internal", role: approver, jurisdiction: "cloud/{account}/*" }
`
	const required = `required_jurisdictions: ["dc/corp-prod/*", "cloud/fin-01/*"]`
	load := func(t *testing.T, replacements ...string) error {
		t.Helper()
		doc := strings.NewReplacer(replacements...).Replace(example(t))
		return Validate(parse(t, doc), Options{LookupEnv: lookupEnv})
	}
	head := "charter:                               # ADR-13, ADR-14, §3.9\n"
	if err := load(t, head, block, required, `required_jurisdictions: ["cloud/*"]`); err != nil {
		t.Fatal(err)
	}
	if err := load(t); err != nil { // absent: as v0.1.0
		t.Fatal(err)
	}
	for name, r := range map[string][]string{
		"approval not required on accounts": {head, block},
		"role not for groups":               {head, strings.Replace(block, "role: approver", "role: admin.full_access", 1), required, `required_jurisdictions: ["cloud/*"]`},
		"bad structure":                     {head, strings.Replace(block, "cloud/{account}/data", "cloud/{account}/app", 1), required, `required_jurisdictions: ["cloud/*"]`},
	} {
		t.Run(name, func(t *testing.T) {
			if err := load(t, r...); err == nil || !strings.Contains(err.Error(), "rule 16") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// account_admin is global: it takes no jurisdictions; every other role needs them.
func TestAccountAdminBinding(t *testing.T) {
	load := func(role, jurisdictions string) error {
		doc := strings.Replace(example(t), "  bindings:\n", "  bindings:\n    - { spiffe_id: \"spiffe://prod.internal/ops/reg\", role: "+role+jurisdictions+" }\n", 1)
		return Validate(parse(t, doc), Options{LookupEnv: lookupEnv})
	}
	if err := load(RoleAccountAdmin, ""); err != nil {
		t.Errorf("no jurisdictions: %v", err)
	}
	if err := load(RoleAccountAdmin, `, jurisdictions: ["*"]`); err == nil || !strings.Contains(err.Error(), "takes no jurisdictions") {
		t.Errorf("with jurisdictions: %v", err)
	}
	if err := load(RoleViewer, ""); err == nil || !strings.Contains(err.Error(), "jurisdictions is required") {
		t.Errorf("a viewer without jurisdictions: %v", err)
	}
}

// TestMovedInstances: a file that still holds instances is refused, with a
// pointer to where they went (.specs/ligo-instances.md §3 rule 1).
func TestMovedInstances(t *testing.T) {
	for _, key := range []string{"instances", "platforms"} {
		_, err := Parse([]byte("secret_stores: [ { type: vault.v1, " + key + ": [] } ]\n"))
		if err == nil || !strings.Contains(err.Error(), "ligo-instances.md") || !strings.Contains(err.Error(), "ligo apply") {
			t.Errorf("%s: %v", key, err)
		}
	}
}
