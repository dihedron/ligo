package bindings

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
)

func example(t *testing.T) *config.Config {
	t.Helper()
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// rules are the example's, plus a platform in a cloud tenancy, and test
// workloads accepted on oracle-prod so that AC-51 reaches the policy.
func rules(t *testing.T) *Rules {
	t.Helper()
	r, err := NewRules(example(t))
	if err != nil {
		t.Fatal(err)
	}
	r.Platforms["cloud-pg"] = Platform{Name: "cloud-pg", Type: "postgres.v1", Zone: "prod", Scope: "cloud/fin-01/payments",
		AllowedTrustDomains: []string{"cloud.internal", "prod.internal"}, IdentityProviderType: "target-local.v1",
		IdentityProviderInstance: "local-prod", SecretStoreType: "vault.v1", SecretStoreInstance: "vault-prod", SecretStorageStrategy: "vault-static"}
	p := r.Platforms["oracle-prod"]
	p.AllowedTrustDomains = append(p.AllowedTrustDomains, "test.internal")
	r.Platforms["oracle-prod"] = p
	return r
}

func slug(err error) string {
	var e *changerequests.Error
	if errors.As(err, &e) {
		return e.Slug
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// plugin is a fake ValidateBinding: grants {"roles": [...]} become sorted
// "role:" privileges, and the requested spec composes the definition, the
// grants and the parameters. twist changes the response.
type plugin struct {
	twist func(*pluginv1.ValidateBindingResponse)
}

func (p *plugin) validate(_ context.Context, req *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error) {
	var g struct {
		Roles []string `json:"roles"`
	}
	_ = json.Unmarshal(req.GetAccessLevelGrantsJson(), &g)
	slices.Sort(g.Roles)
	var privileges []string
	for _, r := range slices.Compact(g.Roles) {
		privileges = append(privileges, "role:"+r)
	}
	params := req.GetParametersJson()
	if len(params) == 0 {
		params = []byte("{}")
	}
	spec, _ := json.Marshal(map[string]json.RawMessage{"definition": req.GetDefinitionJson(), "grants": req.GetAccessLevelGrantsJson(), "parameters": params})
	resp := &pluginv1.ValidateBindingResponse{Valid: true, NormalizedParametersJson: params, RequestedSpecJson: spec, Privileges: privileges}
	if p.twist != nil {
		p.twist(resp)
	}
	return resp, nil
}

func TestNewRules(t *testing.T) {
	p := rules(t).Platforms["oracle-prod"]
	if p.Type != "oracle.v1" || p.Zone != "prod" || p.Scope != "dc/corp-prod" || p.PrincipalPrefix != "svc_" ||
		p.IdentityProviderType != "openldap.v1" || p.IdentityProviderInstance != "ldap-prod" || p.SecretStoreType != "vault.v1" ||
		p.SecretStoreInstance != "vault-prod" || p.SecretStorageStrategy != "vault-static" || !slices.Contains(p.AllowedTrustDomains, "cloud.internal") {
		t.Errorf("platform %+v", p)
	}
}

// TestExpiry: expiresAt is at least an hour and at most max_expiry ahead
// (§3.5).
func TestExpiry(t *testing.T) {
	r := rules(t)
	now := time.Now()
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	for _, tc := range []struct {
		at *time.Time
		ok bool
	}{
		{nil, true}, {at(2 * time.Hour), true}, {at(30 * time.Minute), false}, {at(366 * 24 * time.Hour), false}, {at(364 * 24 * time.Hour), true},
	} {
		if err := r.checkExpiry(tc.at, now); (err == nil) != tc.ok {
			t.Errorf("%v: %v", tc.at, err)
		}
	}
}

// TestRecheck: at apply, a pair the policy now denies, or a party it now
// requires, fails the request; a party it no longer requires does not
// (ADR-14 rule 5).
func TestRecheck(t *testing.T) {
	s := &Service{Rules: rules(t)}
	r := &changerequests.Request{Consent: changerequests.ConsentAll, SourceScope: "cloud/fin-01/payments", TargetScope: "dc/corp-prod/ledger",
		Sides: []changerequests.Side{{Name: "SOURCE"}, {Name: "TARGET"}, {Name: "PARTY:security"}}}
	policy := func(edit func(*governance.Policy)) *governance.Policy {
		p := example(t).Policy()
		edit(p)
		return p
	}
	rule := func(p *governance.Policy) *governance.InterconnectRule {
		i := slices.IndexFunc(p.Interconnects.Rules, func(r governance.InterconnectRule) bool { return r.Name == "cloud-to-dc" })
		return &p.Interconnects.Rules[i]
	}
	for name, tc := range map[string]struct {
		p    *governance.Policy
		want string
	}{
		"unchanged":     {policy(func(*governance.Policy) {}), ""},
		"party dropped": {policy(func(p *governance.Policy) { rule(p).AdditionalApprovals = nil }), ""},
		"party added": {policy(func(p *governance.Policy) {
			rule(p).AdditionalApprovals = append(rule(p).AdditionalApprovals, governance.AdditionalApproval{Name: "dpo", Scope: "sec/privacy"})
		}), "governance-policy-changed"},
		"now denied": {policy(func(p *governance.Policy) { rule(p).Action = "deny" }), "governance-policy-changed"},
	} {
		if err := s.Recheck(r, tc.p); slug(err) != tc.want {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestDecode: a body cannot set what ligo derives (§7.2.3).
func TestDecode(t *testing.T) {
	for _, field := range []string{`"kind":"Binding"`, `"sourceRevision":3`, `"targetRevision":2`, `"requestedSpec":{}`} {
		if _, err := decode([]byte(`{"name":"b","source":"s","target":"t","accessLevel":"read",` + field + `}`)); slug(err) != "validation-failed" {
			t.Errorf("%s: %v", field, err)
		}
	}
	if _, err := decode([]byte(`{"name":"b","source":"s","target":"t","accessLevel":"read","purpose":"p"}`)); err != nil {
		t.Error(err)
	}
}
