//go:build integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/adminauth"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/client"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/server/adminhttp"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/internal/targets"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// directory: olga operates, dora approves dc/corp-prod (LDAP groups).
type directory struct{}

func (directory) Authenticate(_ context.Context, user, password string) (authz.Principal, error) {
	if password != "pw-"+user {
		return authz.Principal{}, adminauth.ErrInvalidCredentials
	}
	return authz.Principal{Name: user, Groups: []string{"cn=" + user}}, nil
}

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

// server starts the admin API with the example configuration, plugins
// that accept everything, and Basic credentials only.
func server(t *testing.T) (*httptest.Server, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), os.Getenv("CI") != "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	data, err := os.ReadFile("../../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	brules, err := bindings.NewRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srules, err := sources.NewRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	trules, err := targets.NewRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	policy := cfg.Policy()
	policy.RequireDistinctApprovers = false // dora decides every side
	requests := &changerequests.Service{DB: pools.App, Policy: policy, TTL: time.Hour, Resources: map[string]changerequests.Resource{}}
	ss := &sources.Service{DB: pools.App, Rules: srules, Requests: requests}
	ts := &targets.Service{DB: pools.App, Rules: trules, Requests: requests, Validate: func(_ context.Context, req *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error) {
		resp := &pluginv1.ValidateTargetResponse{Valid: true, NormalizedDefinitionJson: req.GetDefinitionJson()}
		for _, l := range req.GetAccessLevels() {
			var g struct{ Roles []string }
			_ = json.Unmarshal(l.GetGrantsJson(), &g)
			slices.Sort(g.Roles)
			var privileges []string
			for _, r := range g.Roles {
				privileges = append(privileges, "role:"+r)
			}
			resp.AccessLevels = append(resp.AccessLevels, &pluginv1.NormalizedAccessLevel{Name: l.GetName(), GrantsJson: l.GetGrantsJson(), Privileges: privileges})
		}
		return resp, nil
	}}
	bs := &bindings.Service{DB: pools.App, Rules: brules, Requests: requests, Sources: ss,
		Validate: func(_ context.Context, req *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error) {
			var g struct{ Roles []string }
			_ = json.Unmarshal(req.GetAccessLevelGrantsJson(), &g)
			var privileges []string
			for _, r := range g.Roles {
				privileges = append(privileges, "role:"+r)
			}
			return &pluginv1.ValidateBindingResponse{Valid: true, NormalizedParametersJson: []byte("{}"), RequestedSpecJson: []byte("{}"), Privileges: privileges}, nil
		}}
	requests.Resources["SOURCE"], requests.Resources["TARGET"], requests.Resources["BINDING"] = ss, ts, bs
	az, err := authz.New([]config.RoleBinding{
		{LDAPGroupDN: "cn=olga", Role: config.RoleOperator, Scopes: []string{"dc/corp-prod/*"}},
		{LDAPGroupDN: "cn=dora", Role: config.RoleApprover, Scopes: []string{"dc/corp-prod/*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &adminhttp.Server{Listener: config.AdminListener{AllowBasicAuth: true, RateLimit: config.AdminRateLimit{LoginPerIPPerMin: 1000, LoginPerUserPerMin: 1000}}, Config: cfg, LDAP: directory{}, Authz: az, DB: pools.App,
		Requests: requests, Bindings: bs, Sources: ss, Targets: ts, Catalog: &catalog.Reader{DB: pools.App, Policy: policy}, Logger: slog.New(slog.DiscardHandler)}
	srv := httptest.NewTLSServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, owner
}

// as is a Base for user, printing JSON into out.
func as(t *testing.T, srv *httptest.Server, user string, out *bytes.Buffer) Base {
	t.Helper()
	f := &fake{srv: srv}
	b := f.base(t, "json", out)
	pw := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(pw, []byte("pw-"+user), 0o600)
	b.Username, b.PasswordFile = user, pw
	return b
}

// TestCLI: olga applies a source, a target and a binding of that source
// (inline) from one manifest; dora finds the requests awaiting her and
// approves each side with its payloadSha256; the binding is applied; olga
// revokes it, dora approves; checks and refusals are reported.
func TestCLI(t *testing.T) {
	srv, owner := server(t)
	x := uuid.NewV7().String()[24:]
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from bindings where name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from change_requests where resource_name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from target_access_levels where target_id in (select id from targets where name like $1)", "%"+x)
		_, _ = owner.Exec(ctx, "delete from target_network_flows where target_id in (select id from targets where name like $1)", "%"+x)
		_, _ = owner.Exec(ctx, "delete from targets where name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from sources where name like $1", "%"+x)
	})
	var out bytes.Buffer
	olga, dora := as(t, srv, "olga", &out), as(t, srv, "dora", &out)
	file := manifest(t, fmt.Sprintf(`apiVersion: ligo.dihedron.org/v1alpha1
kind: Binding
name: cli-%[1]s
source: cli-src-%[1]s
target: cli-ledger-%[1]s
accessLevel: read
---
apiVersion: ligo.dihedron.org/v1alpha1
kind: Source
metadata: {name: cli-src-%[1]s}
identity:
  trustDomain: prod.internal
  svidRegex: '^spiffe://prod\.internal/ns/cli/sa/w%[1]s$'
  sampleSpiffeIds: ['spiffe://prod.internal/ns/cli/sa/w%[1]s']
visibility: {mode: PRIVATE}
---
apiVersion: ligo.dihedron.org/v1alpha1
kind: Target
metadata: {name: cli-ledger-%[1]s, platform: oracle-prod, scope: dc/corp-prod/ledger}
definition: {schema: LEDGER_APP}
accessLevels: [{name: read, grants: {roles: [LEDGER_RO_ROLE]}}]
networkFlows: []
visibility: {mode: PRIVATE}
`, x))
	apply := func(file string, answers int) {
		t.Helper()
		out.Reset()
		if err := (&Apply{Base: olga, File: file}).Execute(nil); err != nil {
			t.Fatalf("apply: %v\n%s", err, out.String())
		}
		var applied []filed
		if err := json.Unmarshal(out.Bytes(), &applied); err != nil || len(applied) != answers {
			t.Fatalf("apply answers: %v\n%s", err, out.String())
		}
	}
	// the target awaits approval, so the binding waits too: its source is filed alone
	apply(file, 2)

	// dora approves what awaits her, side by side, with the payloadSha256 she was shown
	approveAll := func(kind, name string, wantErr string) {
		t.Helper()
		out.Reset()
		if err := (&ChangeRequestList{Base: dora, AwaitingMe: true, Kind: kind, Name: name}).Execute(nil); err != nil {
			t.Fatal(err)
		}
		var page struct{ Items []map[string]any }
		_ = json.Unmarshal(out.Bytes(), &page)
		if len(page.Items) != 1 {
			t.Fatalf("awaiting %s %s: %s", kind, name, out.String())
		}
		cr := page.Items[0]
		for _, side := range cr["awaitingApproval"].([]any) {
			out.Reset()
			err := (&ChangeRequestApprove{Base: dora, SHA256: cr["payloadSha256"].(string), Side: side.(string), Comment: "cli",
				Args: crID{cr["id"].(string)}}).Execute(nil)
			if wantErr != "" {
				var p *client.Problem
				if !errors.As(err, &p) || !strings.Contains(p.Type, wantErr) {
					t.Fatalf("approve %s %s: %v, want %s", kind, name, err, wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("approve %s %s side %v: %v", kind, name, side, err)
			}
			var answers []filed
			if json.Unmarshal(out.Bytes(), &answers) == nil && len(answers) == 1 && answers[0].ChangeRequest["status"] == "APPLIED" {
				return // consent ANY: one side was enough
			}
		}
	}
	approveAll("target", "cli-ledger-"+x, "")
	approveAll("source", "cli-src-"+x, "")
	// now the binding alone
	apply(manifest(t, fmt.Sprintf("{kind: Binding, name: cli-%[1]s, source: cli-src-%[1]s, target: cli-ledger-%[1]s, accessLevel: read}\n", x)), 1)
	approveAll("binding", "cli-"+x, "")

	// a new source and its binding to the existing target: inline, the binding waits for the source
	apply(manifest(t, fmt.Sprintf(`kind: Source
metadata: {name: cli-src2-%[1]s}
identity:
  trustDomain: prod.internal
  svidRegex: '^spiffe://prod\.internal/ns/cli2/sa/w%[1]s$'
  sampleSpiffeIds: ['spiffe://prod.internal/ns/cli2/sa/w%[1]s']
visibility: {mode: PRIVATE}
---
{kind: Binding, name: cli2-%[1]s, source: cli-src2-%[1]s, target: cli-ledger-%[1]s, accessLevel: read}
`, x)), 1)
	approveAll("binding", "cli2-"+x, "dependency-pending")
	approveAll("source", "cli-src2-"+x, "")
	approveAll("binding", "cli2-"+x, "")

	out.Reset()
	if err := (&Get{Base: olga, Args: ResourceArgs{"binding", "cli-" + x}}).Execute(nil); err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	_ = json.Unmarshal(out.Bytes(), &b)
	if client.Lookup(b, "status.phase") != "PROVISIONING" {
		t.Fatalf("binding: %s", out.String())
	}

	out.Reset()
	if err := (&GovernanceCheck{Base: olga, File: file}).Execute(nil); err != nil || !strings.Contains(out.String(), `"consent": "ALL"`) {
		t.Errorf("governance check: %v\n%s", err, out.String())
	}
	if err := (&Apply{Base: olga, File: manifest(t, fmt.Sprintf("kind: Target\nmetadata: {name: cli-ledger-%s, platform: oracle-prod, scope: dc/corp-prod/ledger}\n"+
		"definition: {schema: LEDGER_APP}\naccessLevels: [{name: read, grants: {roles: [LEDGER_RO_ROLE]}}]\n", x))}).Execute(nil); err == nil ||
		!strings.Contains(err.Error(), "exists at revision 1: add expectedRevision: 1") {
		t.Errorf("an existing target: %v", err)
	}
	if err := (&MaintenanceOn{Base: dora, Reason: "x"}).Execute(nil); err == nil || !strings.Contains(err.Error(), "403 forbidden") {
		t.Errorf("maintenance on as an approver: %v", err)
	}

	// no workflow engine here: the binding stays PROVISIONING unless marked ACTIVE
	if _, err := owner.Exec(context.Background(), "update bindings set phase = 'ACTIVE' where name = $1", "cli-"+x); err != nil {
		t.Fatal(err)
	}
	revision := int64(client.Lookup(b, "metadata.revision").(float64))
	out.Reset()
	if err := (&Delete{Base: olga, ExpectedRevision: revision, Args: ResourceArgs{"binding", "cli-" + x}}).Execute(nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	approveAll("binding", "cli-"+x, "")
	out.Reset()
	if err := (&Get{Base: olga, Args: ResourceArgs{"binding", "cli-" + x}}).Execute(nil); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(out.Bytes(), &b)
	if client.Lookup(b, "status.phase") != "DELETING" {
		t.Errorf("after the revocation: %s", out.String())
	}
}
