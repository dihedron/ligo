package targets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/flows"
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

func rules(t *testing.T) *Rules {
	t.Helper()
	r, err := NewRules(example(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// plugin is a fake ValidateTarget: grants {"roles": [...]} become sorted
// "role:" privileges; with check_existence, the schema LEDGER_MISSING does
// not exist. It records the requests.
type plugin struct {
	calls []*pluginv1.ValidateTargetRequest
	twist func(*pluginv1.ValidateTargetResponse)
}

func (p *plugin) validate(_ context.Context, req *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error) {
	p.calls = append(p.calls, req)
	var def struct {
		Schema string `json:"schema"`
	}
	_ = json.Unmarshal(req.GetDefinitionJson(), &def)
	if req.GetCheckExistence() && def.Schema == "LEDGER_MISSING" {
		return &pluginv1.ValidateTargetResponse{Errors: []string{"definition.schema: LEDGER_MISSING does not exist"}}, nil
	}
	resp := &pluginv1.ValidateTargetResponse{Valid: true, NormalizedDefinitionJson: req.GetDefinitionJson()}
	for _, l := range req.GetAccessLevels() {
		var g struct {
			Roles []string `json:"roles"`
		}
		_ = json.Unmarshal(l.GetGrantsJson(), &g)
		slices.Sort(g.Roles)
		var privileges []string
		for _, r := range slices.Compact(g.Roles) {
			privileges = append(privileges, "role:"+r)
		}
		grants, _ := json.Marshal(map[string]any{"roles": slices.Compact(g.Roles)})
		resp.AccessLevels = append(resp.AccessLevels, &pluginv1.NormalizedAccessLevel{Name: l.GetName(), GrantsJson: grants, Privileges: privileges})
	}
	if p.twist != nil {
		p.twist(resp)
	}
	return resp, nil
}

func ledger() Target {
	return Target{
		Metadata:   Metadata{Name: "ledger-schema", Platform: "oracle-prod", Scope: "dc/corp-prod/ledger"},
		Definition: json.RawMessage(`{"schema":"LEDGER_APP","serviceName":"LEDGER.prod.internal"}`),
		AccessLevels: []AccessLevel{
			{Name: "read", Grants: json.RawMessage(`{"roles":["LEDGER_RO_ROLE"]}`)},
			{Name: "write", Grants: json.RawMessage(`{"roles":["LEDGER_RW_ROLE","LEDGER_RO_ROLE"]}`)},
		},
		NetworkFlows: flowsOf(`[{"name":"ledger-listener","purpose":"DATA","protocol":"TCP","destination":"ledger-db.prod.internal","ports":[1522],"tls":true,"serverName":"ledger-db.prod.internal"}]`),
	}
}

func flowsOf(s string) []flows.Flow {
	var f []flows.Flow
	if err := json.Unmarshal([]byte(s), &f); err != nil {
		panic(err)
	}
	return f
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

// TestValidate runs the target pipeline's own checks on a new target
// (§7.2.3 steps 1, 2, 3 and 5, §3.3).
func TestValidate(t *testing.T) {
	r := rules(t)
	flow := func(dest string) []flows.Flow {
		return flowsOf(`[{"name":"f","purpose":"DATA","protocol":"TCP","destination":"` + dest + `","tls":false}]`)
	}
	for name, tc := range map[string]struct {
		edit  func(*Target)
		twist func(*pluginv1.ValidateTargetResponse)
		want  string
	}{
		"valid":                               {func(*Target) {}, nil, ""},
		"unknown platform":                    {func(t *Target) { t.Metadata.Platform = "db2-prod" }, nil, "validation-failed"},
		"scope outside target_scopes (AC-63)": {func(t *Target) { t.Metadata.Scope = "cloud/fin-01/payments" }, nil, "validation-failed"},
		"resource missing (AC-63)":            {func(t *Target) { t.Definition = json.RawMessage(`{"schema":"LEDGER_MISSING"}`) }, nil, "validation-failed"},
		"flow to another host (AC-64)": {func(t *Target) {
			t.NetworkFlows = flowsOf(`[{"name":"f","purpose":"DATA","protocol":"TCP","destination":"evil.example.org","ports":[443],"tls":true}]`)
		}, nil, "flow-destination-not-allowed"},
		"flow to another port (AC-64)": {func(t *Target) {
			t.NetworkFlows = flowsOf(`[{"name":"f","purpose":"DATA","protocol":"TCP","destination":"ledger-db.prod.internal","ports":[1600],"tls":true}]`)
		}, nil, "flow-destination-not-allowed"},
		"flow schema":             {func(t *Target) { t.NetworkFlows = flow("ledger-db.prod.internal") }, nil, "validation-failed"},
		"no access level":         {func(t *Target) { t.AccessLevels = nil }, nil, "validation-failed"},
		"duplicate level":         {func(t *Target) { t.AccessLevels[1].Name = "read" }, nil, "validation-failed"},
		"level name":              {func(t *Target) { t.AccessLevels[0].Name = "Read" }, nil, "validation-failed"},
		"privileges are output":   {func(t *Target) { t.AccessLevels[0].Privileges = []string{"role:X"} }, nil, "validation-failed"},
		"scope and state are set": {func(t *Target) { t.Metadata.State = "ACTIVE" }, nil, "validation-failed"},
		"plugin: unsorted privileges": {func(*Target) {}, func(r *pluginv1.ValidateTargetResponse) {
			r.AccessLevels[1].Privileges = []string{"role:LEDGER_RW_ROLE", "role:LEDGER_RO_ROLE"}
		}, "validation-failed"},
		"plugin: levels out of order": {func(*Target) {}, func(r *pluginv1.ValidateTargetResponse) {
			r.AccessLevels[0], r.AccessLevels[1] = r.AccessLevels[1], r.AccessLevels[0]
		}, "validation-failed"},
	} {
		t.Run(name, func(t *testing.T) {
			p := &plugin{twist: tc.twist}
			tg := ledger()
			tc.edit(&tg)
			err := r.validate(context.Background(), p.validate, &tg, nil)
			if slug(err) != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if err != nil {
				return
			}
			m := tg.Metadata
			if tg.Kind != "Target" || m.State != "ACTIVE" || m.PlatformType != "oracle.v1" || m.PlatformScope != "dc/corp-prod" || m.Zone != "prod" ||
				tg.Visibility.Mode != "PRIVATE" || tg.AccessLevels[0].State != "ACTIVE" {
				t.Errorf("not normalized: %+v", tg)
			}
			if got := strings.Join(tg.AccessLevels[1].Privileges, ","); got != "role:LEDGER_RO_ROLE,role:LEDGER_RW_ROLE" {
				t.Errorf("privileges %s", got)
			}
			if !p.calls[0].GetCheckExistence() || p.calls[0].GetInstance() != "oracle-prod" || len(p.calls[0].GetNetworkFlows()) != 1 {
				t.Errorf("plugin request %v", p.calls[0])
			}
		})
	}
}

// TestCheckExistenceDefault: check_existence defaults to true (§7.2.3).
func TestCheckExistenceDefault(t *testing.T) {
	cfg := example(t)
	cfg.PlatformProviders[0].Platforms[0].CheckExistence = nil
	r, err := NewRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Platforms["oracle-prod"].CheckExistence {
		t.Error("check_existence does not default to true")
	}
}
