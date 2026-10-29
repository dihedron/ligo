//go:build integration

package bindings

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// insecure: CI's container has no TLS; the lab's DSNs use verify-full.
var insecure = os.Getenv("CI") != ""

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

func caller(name string, grants ...authz.Grant) changerequests.Caller {
	return changerequests.Caller{Principal: authz.Principal{Name: name}, Grants: grants}
}

func role(r string, scopes ...string) authz.Grant { return authz.Grant{Role: r, Scopes: scopes} }

var (
	cloudOp   = caller("carla", role(config.RoleOperator, "cloud/fin-01/*"))
	cloudLead = caller("luca", role(config.RoleApprover, "cloud/fin-01/*"))
	fin02Op   = caller("fede", role(config.RoleOperator, "cloud/fin-02/*"))
	ledgerOp  = caller("lea", role(config.RoleOperator, "dc/corp-prod/ledger"))
	ledgerApp = caller("bob", role(config.RoleApprover, "dc/corp-prod/ledger"))
	dcOp      = caller("dino", role(config.RoleOperator, "dc/corp-prod"))
	dcApp     = caller("dora", role(config.RoleApprover, "dc/corp-prod"))
	sec       = caller("sara", role(config.RoleApprover, "sec/infosec"))
	marco     = caller("marco", role(config.RoleApprover, "dc/corp-prod/ledger", "sec/infosec"))
	testOp    = caller("tina", role(config.RoleOperator, "dc/corp-test/*"))
)

// world is a set of sources and targets committed for one test.
type world struct {
	suffix                             string
	cloudSrc, dcSrc, testSrc, fin02Src string
	ledger, dcShared, cloudTgt         string
	ledgerID                           uuid.UUID
}

func setup(t *testing.T) (*Service, *pgxpool.Pool, *world, *plugin) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), insecure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	cfg := example(t)
	p := &plugin{}
	s := &Service{DB: pools.App, Rules: rules(t), Validate: p.validate}
	s.Requests = &changerequests.Service{DB: pools.App, Policy: cfg.Policy(), TTL: cfg.Authorization.Approval.ChangeRequestTTL,
		Resources: map[string]changerequests.Resource{"BINDING": s}}
	return s, owner, newWorld(t, owner), p
}

func newWorld(t *testing.T, o *pgxpool.Pool) *world {
	t.Helper()
	ctx := context.Background()
	x := uuid.NewV7().String()[24:]
	w := &world{suffix: x, cloudSrc: "fin-01-payments-src-" + x, dcSrc: "dc-src-" + x, testSrc: "test-src-" + x, fin02Src: "fin-02-x-src-" + x,
		ledger: "ledger-" + x, dcShared: "dc-shared-" + x, cloudTgt: "cloud-tgt-" + x, ledgerID: uuid.NewV7()}
	sources := []struct{ name, scope, td, regex, vis, to string }{
		{w.cloudSrc, "cloud/fin-01/payments", "cloud.internal", `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/` + x + `$`, "LISTED", `["dc/corp-prod/*"]`},
		{w.dcSrc, "dc/corp-prod", "prod.internal", `^spiffe://prod\.internal/ns/payments/sa/` + x + `$`, "PUBLIC", "[]"},
		{w.testSrc, "dc/corp-test", "test.internal", `^spiffe://test\.internal/ns/payments/sa/` + x + `$`, "PUBLIC", "[]"},
		{w.fin02Src, "cloud/fin-02/x", "cloud.internal", `^spiffe://cloud\.internal/acct/fin-02/tenant/x/sa/` + x + `$`, "PUBLIC", "[]"},
	}
	targets := []struct {
		id                   uuid.UUID
		name, platform, typ  string
		scope, platformScope string
	}{
		{w.ledgerID, w.ledger, "oracle-prod", "oracle.v1", "dc/corp-prod/ledger", "dc/corp-prod"},
		{uuid.NewV7(), w.dcShared, "oracle-prod", "oracle.v1", "dc/corp-prod", "dc/corp-prod"},
		{uuid.NewV7(), w.cloudTgt, "cloud-pg", "postgres.v1", "cloud/fin-01/payments", "cloud/fin-01/payments"},
	}
	err := pgx.BeginFunc(ctx, o, func(tx pgx.Tx) error {
		for _, s := range sources {
			if _, err := tx.Exec(ctx, `insert into sources (id, name, scope, trust_domain, svid_regex, visibility, visible_to, created_by, updated_by)
				values ($1, $2, $3, $4, $5, $6, $7::jsonb, 't', 't')`, uuid.NewV7(), s.name, s.scope, s.td, s.regex, s.vis, s.to); err != nil {
				return err
			}
		}
		for _, tg := range targets {
			if _, err := tx.Exec(ctx, `insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, visibility, created_by, updated_by)
				values ($1, $2, $3, $4, 'prod', $5, $6, '{"schema":"LEDGER_APP"}', 'PUBLIC', 't', 't')`, tg.id, tg.name, tg.platform, tg.typ, tg.scope, tg.platformScope); err != nil {
				return err
			}
			for _, l := range []struct{ name, grants, privileges string }{
				{"read", `{"roles":["LEDGER_RO_ROLE"]}`, `["role:LEDGER_RO_ROLE"]`},
				{"write", `{"roles":["LEDGER_RO_ROLE","LEDGER_RW_ROLE"]}`, `["role:LEDGER_RO_ROLE","role:LEDGER_RW_ROLE"]`},
			} {
				if _, err := tx.Exec(ctx, `insert into target_access_levels (target_id, name, grants, privileges) values ($1, $2, $3::jsonb, $4::jsonb)`,
					tg.id, l.name, l.grants, l.privileges); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = o.Exec(ctx, "delete from change_requests where resource_type = 'BINDING' and resource_name like $1", "%"+x+"%")
		_, _ = o.Exec(ctx, "delete from bindings where name like $1", "%"+x+"%")
		_, _ = o.Exec(ctx, "delete from target_access_levels where target_id in (select id from targets where name like $1)", "%"+x)
		_, _ = o.Exec(ctx, "delete from targets where name like $1", "%"+x)
		_, _ = o.Exec(ctx, "delete from sources where name like $1", "%"+x)
	})
	return w
}

func body(name, source, target, level string, extra ...string) []byte {
	s := fmt.Sprintf(`{"name":%q,"source":%q,"target":%q,"accessLevel":%q`, name, source, target, level)
	for _, e := range extra {
		s += "," + e
	}
	return []byte(s + "}")
}

func sides(r *changerequests.Request) string {
	var out []string
	for _, s := range r.Sides {
		out = append(out, s.Name+"="+s.Basis)
	}
	return strings.Join(out, ",")
}

// approve has each caller approve r, the last one completing it.
func approve(t *testing.T, s *Service, r *changerequests.Request, cs ...changerequests.Caller) {
	t.Helper()
	for _, c := range cs {
		if _, err := s.Requests.Approve(context.Background(), c, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
			t.Fatalf("%s approves: %v", c.ID(), err)
		}
	}
}

func bindingRow(t *testing.T, o *pgxpool.Pool, name string) (phase, workflow, principal, strategy string, revision int64) {
	t.Helper()
	err := o.QueryRow(context.Background(), `select phase, workflow_id, derived_principal_name, secret_storage_strategy, revision
		from bindings where name = $1`, name).Scan(&phase, &workflow, &principal, &strategy, &revision)
	if err != nil {
		t.Fatalf("binding %s: %v", name, err)
	}
	return
}

func status(t *testing.T, o *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var st string
	if err := o.QueryRow(context.Background(), "select status from change_requests where id = $1", id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestAC44: the sides of the four topologies, each applied once its
// approvers act.
func TestAC44(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name           string
		by             changerequests.Caller
		source, target string
		sides          string
		approvers      []changerequests.Caller
	}{
		{"fin-01-payments-cc-" + w.suffix, cloudOp, w.cloudSrc, w.cloudTgt, "TARGET=HUMAN", []changerequests.Caller{cloudLead}},
		{"dd-" + w.suffix, dcOp, w.dcSrc, w.dcShared, "TARGET=HUMAN", []changerequests.Caller{dcApp}},
		{"fin-01-payments-cd-" + w.suffix, cloudOp, w.cloudSrc, w.ledger, "TARGET=HUMAN,SOURCE=HUMAN,PARTY:security=HUMAN", []changerequests.Caller{ledgerApp, cloudLead, sec}},
		{"dc-" + w.suffix, dcOp, w.dcSrc, w.cloudTgt, "TARGET=HUMAN,SOURCE=HUMAN", []changerequests.Caller{cloudLead, dcApp}},
	} {
		r, err := s.Create(ctx, tc.by, body(tc.name, tc.source, tc.target, "read"))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := sides(r); got != tc.sides {
			t.Errorf("%s: sides %s, want %s", tc.name, got, tc.sides)
		}
		approve(t, s, r, tc.approvers...)
		if st := status(t, o, r.ID); st != "APPLIED" {
			t.Errorf("%s: %s", tc.name, st)
		}
		if phase, _, _, _, _ := bindingRow(t, o, tc.name); phase != "PROVISIONING" {
			t.Errorf("%s: phase %s", tc.name, phase)
		}
	}
}

// TestApplied: an applied CREATE writes a PROVISIONING binding with its
// workflow, principal name and storage strategy, and audits APPLY_STARTED.
func TestApplied(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "dd-" + w.suffix
	r, err := s.Create(ctx, dcOp, body(name, w.dcSrc, w.dcShared, "write", `"parameters":{"connectionLimit":20}`, `"purpose":"posting"`))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, dcApp)
	phase, workflow, principal, strategy, revision := bindingRow(t, o, name)
	var id uuid.UUID
	var spec string
	if err := o.QueryRow(ctx, "select id, requested_spec->>'parameters' from bindings where name = $1", name).Scan(&id, &spec); err != nil {
		t.Fatal(err)
	}
	if phase != "PROVISIONING" || workflow != "ligo:apply:"+id.String()+":r1:a1" || !strings.HasPrefix(principal, "svc_") || len(principal) != 20 ||
		strategy != "vault-static" || revision != 1 || spec != `{"connectionLimit": 20}` {
		t.Errorf("binding %s %s %s %s %d %s", phase, workflow, principal, strategy, revision, spec)
	}
	var started int
	if err := o.QueryRow(ctx, "select count(*) from audit_log where change_request_id = $1 and action = 'APPLY_STARTED'", r.ID).Scan(&started); err != nil || started != 1 {
		t.Errorf("APPLY_STARTED %d (%v)", started, err)
	}
	if _, err := s.Create(ctx, dcOp, body("dd2-"+w.suffix, w.dcSrc, w.dcShared, "read")); slug(err) != "binding-exists" {
		t.Errorf("second binding of the pair: %v", err)
	}
}

// TestAC47: a target owner offering a binding to another scope's source
// waits for the source side; declining it rejects the request.
func TestAC47(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	r, err := s.Create(ctx, ledgerOp, body("fin-01-payments-o-"+w.suffix, w.cloudSrc, w.ledger, "read"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || !strings.Contains(sides(r), "SOURCE=HUMAN") {
		t.Fatalf("request %s %s", r.Status, sides(r))
	}
	if _, err := s.Requests.Decline(ctx, cloudLead, r.ID, "SOURCE", "not ours"); err != nil {
		t.Fatal(err)
	}
	if st := status(t, o, r.ID); st != "REJECTED" {
		t.Errorf("status %s", st)
	}
}

// TestAC48: a source owner's request waits for the target side; its own
// side is approved at once only where approval is not required.
func TestAC48(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, fin02Op, body("fin-02-x-b-"+w.suffix, w.fin02Src, w.cloudTgt, "read")); slug(err) != "interconnect-denied" {
		t.Errorf("fin-02 to fin-01 (no rule): %v", err)
	}
	r, err := s.Create(ctx, fin02Op, body("fin-02-x-a-"+w.suffix, w.fin02Src, w.ledger, "read"))
	if err != nil {
		t.Fatal(err)
	}
	if got := sides(r); got != "TARGET=HUMAN,SOURCE=AUTO,PARTY:security=HUMAN" {
		t.Errorf("sides %s", got)
	}
	var n int
	if err := o.QueryRow(ctx, "select count(*) from bindings where name = $1", "fin-02-x-a-"+w.suffix).Scan(&n); err != nil || n != 0 {
		t.Errorf("provisioned before the target side approved: %d (%v)", n, err)
	}
}

// TestAC49: one approver of two sides must choose one, and cannot approve
// both when distinct approvers are required.
func TestAC49(t *testing.T) {
	s, _, w, _ := setup(t)
	ctx := context.Background()
	r, err := s.Create(ctx, cloudOp, body("fin-01-payments-m-"+w.suffix, w.cloudSrc, w.ledger, "read"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Requests.Approve(ctx, marco, r.ID, r.PayloadSHA256, "", "ok"); slug(err) != "side-required" {
		t.Errorf("without side: %v", err)
	}
	if _, err := s.Requests.Approve(ctx, marco, r.ID, r.PayloadSHA256, "TARGET", "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Requests.Approve(ctx, marco, r.ID, r.PayloadSHA256, "PARTY:security", "ok"); slug(err) != "distinct-approver-required" {
		t.Errorf("second side: %v", err)
	}
}

// TestAC51: a denied pair is refused, naming the rule; only the audit
// entry is stored.
func TestAC51(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "t-" + w.suffix
	_, err := s.Create(ctx, testOp, body(name, w.testSrc, w.ledger, "read"))
	if slug(err) != "interconnect-denied" || !strings.Contains(err.Error(), "no-test-to-prod") {
		t.Errorf("test to prod: %v", err)
	}
	var crs, denied int
	if err := o.QueryRow(ctx, `select (select count(*) from change_requests where resource_name = $1),
		(select count(*) from audit_log where resource_name = $1 and action = 'CR_INTERCONNECT_DENIED')`, name).Scan(&crs, &denied); err != nil || crs != 0 || denied != 1 {
		t.Errorf("%d requests, %d audit entries (%v)", crs, denied, err)
	}
}

// TestAC05: a changed target, or a plugin that now normalizes or refuses
// differently, fails the request at approval; nothing is applied.
func TestAC05(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*testing.T, *pgxpool.Pool, *world, *plugin)
		want   string
	}{
		"target changed (AC-05a)": {func(t *testing.T, o *pgxpool.Pool, w *world, _ *plugin) {
			if _, err := o.Exec(context.Background(), "update targets set revision = revision + 1 where id = $1", w.ledgerID); err != nil {
				t.Fatal(err)
			}
		}, "normalization-drift"},
		"plugin upgraded (AC-05a)": {func(_ *testing.T, _ *pgxpool.Pool, _ *world, p *plugin) {
			p.twist = func(r *pluginv1.ValidateBindingResponse) { r.RequestedSpecJson = []byte(`{"v":2}`) }
		}, "normalization-drift"},
		"role no longer grantable (AC-05b)": {func(_ *testing.T, _ *pgxpool.Pool, _ *world, p *plugin) {
			p.twist = func(r *pluginv1.ValidateBindingResponse) {
				r.Valid, r.Errors = false, []string{"LEDGER_RW_ROLE is not in grantable_roles"}
			}
		}, "validation-failed"},
	} {
		t.Run(name, func(t *testing.T) {
			s, o, w, p := setup(t)
			ctx := context.Background()
			r, err := s.Create(ctx, cloudOp, body("fin-01-payments-d-"+w.suffix, w.cloudSrc, w.ledger, "write"))
			if err != nil {
				t.Fatal(err)
			}
			approve(t, s, r, cloudLead, sec)
			tc.change(t, o, w, p)
			_, err = s.Requests.Approve(ctx, ledgerApp, r.ID, r.PayloadSHA256, "", "ok")
			if slug(err) != tc.want || (tc.want == "validation-failed" && !strings.Contains(err.Error(), "LEDGER_RW_ROLE")) {
				t.Errorf("err = %v, want %s", err, tc.want)
			}
			if st := status(t, o, r.ID); st != "FAILED_TO_APPLY" {
				t.Errorf("status %s", st)
			}
		})
	}
}

// TestAC52: a party the policy now requires fails the request at apply.
func TestAC52(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	r, err := s.Create(ctx, cloudOp, body("fin-01-payments-p-"+w.suffix, w.cloudSrc, w.ledger, "read"))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, cloudLead, sec)
	p := example(t).Policy()
	for i := range p.Interconnects.Rules {
		if p.Interconnects.Rules[i].Name == "cloud-to-dc" {
			p.Interconnects.Rules[i].AdditionalApprovals = append(p.Interconnects.Rules[i].AdditionalApprovals, governance.AdditionalApproval{Name: "dpo", Scope: "sec/privacy"})
		}
	}
	s.Requests.Policy = p
	if _, err := s.Requests.Approve(ctx, ledgerApp, r.ID, r.PayloadSHA256, "", "ok"); slug(err) != "governance-policy-changed" {
		t.Errorf("err = %v", err)
	}
	if st := status(t, o, r.ID); st != "FAILED_TO_APPLY" {
		t.Errorf("status %s", st)
	}
}

// TestUpdate: raising the level of an active binding starts revision 2; a
// busy binding keeps the approval pending.
func TestUpdate(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "dd-" + w.suffix
	r, err := s.Create(ctx, dcOp, body(name, w.dcSrc, w.dcShared, "read"))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, dcApp)
	u, err := s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.dcShared, "write", `"expectedRevision":1`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Requests.Approve(ctx, dcApp, u.ID, u.PayloadSHA256, "", "ok"); slug(err) != "binding-busy" {
		t.Errorf("busy: %v", err)
	}
	if st := status(t, o, u.ID); st != "PENDING" {
		t.Errorf("after busy: %s", st)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	approve(t, s, u, dcApp)
	phase, workflow, _, _, revision := bindingRow(t, o, name)
	var level string
	if err := o.QueryRow(ctx, "select access_level from bindings where name = $1", name).Scan(&level); err != nil {
		t.Fatal(err)
	}
	if phase != "PROVISIONING" || revision != 2 || !strings.HasSuffix(workflow, ":r2:a2") || level != "write" {
		t.Errorf("binding %s %s %d %s", phase, workflow, revision, level)
	}
	if _, err := s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.cloudTgt, "write", `"expectedRevision":2`)); slug(err) != "immutable-field" {
		t.Errorf("another target: %v", err)
	}
	if _, err := s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.dcShared, "write", `"expectedRevision":1`)); slug(err) != "revision-conflict" {
		t.Errorf("stale revision: %v", err)
	}
}

// active creates the binding name and makes it ACTIVE, as a finished
// workflow would; approvers approve its creation.
func active(t *testing.T, s *Service, o *pgxpool.Pool, by changerequests.Caller, name, source, target, level string, extra string, approvers ...changerequests.Caller) {
	t.Helper()
	var r *changerequests.Request
	var err error
	if extra != "" {
		r, err = s.Create(context.Background(), by, body(name, source, target, level, extra))
	} else {
		r, err = s.Create(context.Background(), by, body(name, source, target, level))
	}
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, approvers...)
	if _, err := o.Exec(context.Background(), "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
}

// TestRevoke: either owner, or the platform owner, revokes alone with
// consent ANY; a side in a self-service scope revokes at once; the binding
// is DELETING with its active snapshot cleared (ADR-13 rules 4 and 5).
func TestRevoke(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "fin-01-payments-r-" + w.suffix
	active(t, s, o, cloudOp, name, w.cloudSrc, w.ledger, "read", "", ledgerApp, cloudLead, sec)
	if _, err := s.Delete(ctx, testOp, name, 1, "", nil); slug(err) != "not-found" {
		t.Errorf("a stranger revokes: %v", err)
	}
	r, err := s.Delete(ctx, dcOp, name, 1, "", nil) // platform owner, containment
	if err != nil {
		t.Fatal(err)
	}
	if r.Consent != changerequests.ConsentAny || sides(r) != "PLATFORM=HUMAN" {
		t.Fatalf("platform revocation %s %s", r.Consent, sides(r))
	}
	if err := s.Requests.Withdraw(ctx, dcOp, r.ID, "later"); err != nil {
		t.Fatal(err)
	}
	r, err = s.Delete(ctx, ledgerOp, name, 1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if sides(r) != "TARGET=HUMAN" {
		t.Fatalf("target revocation %s", sides(r))
	}
	approve(t, s, r, ledgerApp)
	phase, workflow, _, _, revision := bindingRow(t, o, name)
	var id uuid.UUID
	var cleared bool
	if err := o.QueryRow(ctx, "select id, active_spec is null from bindings where name = $1", name).Scan(&id, &cleared); err != nil {
		t.Fatal(err)
	}
	if phase != "DELETING" || workflow != "ligo:delete:"+id.String()+":r1:a2" || revision != 1 || !cleared {
		t.Errorf("binding %s %s %d cleared=%t", phase, workflow, revision, cleared)
	}
	if _, err := s.Delete(ctx, ledgerOp, name, 1, "", nil); err != nil {
		t.Fatal(err) // filed; the apply finds it busy
	}

	// fin-02 does not require approval: its owner revokes at once
	auto := "fin-02-x-r-" + w.suffix
	active(t, s, o, fin02Op, auto, w.fin02Src, w.ledger, "read", "", ledgerApp, sec)
	r, err = s.Delete(ctx, fin02Op, auto, 1, "", nil)
	if err != nil || r.Status != "APPLIED" || sides(r) != "SOURCE=AUTO" {
		t.Fatalf("self-service revocation: %v %+v", err, r)
	}
	if phase, _, _, _, _ := bindingRow(t, o, auto); phase != "DELETING" {
		t.Errorf("phase %s", phase)
	}
}

// TestDowngrade: a lower level or an earlier expiry only removes access,
// consent ANY; a higher level, a later expiry or new parameters add or
// change it, consent ALL (ADR-13 rule 5, §3.10).
func TestDowngrade(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "fin-01-payments-g-" + w.suffix
	expiry := `"expiresAt":"` + time.Now().Add(240*time.Hour).UTC().Format(time.RFC3339) + `"`
	active(t, s, o, cloudOp, name, w.cloudSrc, w.ledger, "write", expiry, ledgerApp, cloudLead, sec)
	sooner := `"expiresAt":"` + time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339) + `"`
	later := `"expiresAt":"` + time.Now().Add(480*time.Hour).UTC().Format(time.RFC3339) + `"`
	for _, tc := range []struct {
		level, extra, consent, sides string
	}{
		{"read", expiry, "ANY", "TARGET=HUMAN"},
		{"write", sooner, "ANY", "TARGET=HUMAN"},
		{"read", sooner, "ANY", "TARGET=HUMAN"},
		{"write", later, "ALL", "TARGET=HUMAN,SOURCE=HUMAN,PARTY:security=HUMAN"},
		{"write", expiry + `,"parameters":{"connectionLimit":5}`, "ALL", "TARGET=HUMAN,SOURCE=HUMAN,PARTY:security=HUMAN"},
	} {
		r, err := s.Update(ctx, ledgerOp, name, body(name, w.cloudSrc, w.ledger, tc.level, tc.extra, `"expectedRevision":1`))
		if err != nil {
			t.Fatalf("%s %s: %v", tc.level, tc.extra, err)
		}
		if r.Consent != tc.consent || sides(r) != tc.sides {
			t.Errorf("%s %s: %s %s", tc.level, tc.extra, r.Consent, sides(r))
		}
		if err := s.Requests.Withdraw(ctx, ledgerOp, r.ID, "test"); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Update(ctx, ledgerOp, name, body(name, w.cloudSrc, w.ledger, "read", expiry, `"expectedRevision":1`))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, ledgerApp)
	var level string
	var revision int64
	if err := o.QueryRow(ctx, "select access_level, revision from bindings where name = $1", name).Scan(&level, &revision); err != nil || level != "read" || revision != 2 {
		t.Errorf("binding %s r%d (%v)", level, revision, err)
	}
}

// TestFailedUpdate: an update of a FAILED binding rotates its secrets
// (§3.11).
func TestFailedUpdate(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "dd-" + w.suffix
	active(t, s, o, dcOp, name, w.dcSrc, w.dcShared, "read", "", dcApp)
	if _, err := o.Exec(ctx, "update bindings set phase = 'FAILED', rotate_static_secrets = false where name = $1", name); err != nil {
		t.Fatal(err)
	}
	r, err := s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.dcShared, "write", `"expectedRevision":1`))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, dcApp)
	var rotate bool
	if err := o.QueryRow(ctx, "select rotate_static_secrets from bindings where name = $1", name).Scan(&rotate); err != nil || !rotate {
		t.Errorf("rotate_static_secrets %t (%v)", rotate, err)
	}
}

// TestAC50: two approvers completing a request at the same moment apply it
// exactly once.
func TestAC50(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "fin-01-payments-c-" + w.suffix
	r, err := s.Create(ctx, cloudOp, body(name, w.cloudSrc, w.ledger, "read"))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, cloudLead)
	errs := make(chan error, 2)
	for _, c := range []changerequests.Caller{ledgerApp, sec} {
		go func() {
			_, err := s.Requests.Approve(ctx, c, r.ID, r.PayloadSHA256, "", "ok")
			errs <- err
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	var applied, started, bindings int
	if err := o.QueryRow(ctx, `select (select count(*) from change_requests where id = $1 and status = 'APPLIED'),
		(select count(*) from audit_log where change_request_id = $1 and action = 'APPLY_STARTED'),
		(select count(*) from bindings where name = $2)`, r.ID, name).Scan(&applied, &started, &bindings); err != nil ||
		applied != 1 || started != 1 || bindings != 1 {
		t.Errorf("applied %d, started %d, bindings %d (%v)", applied, started, bindings, err)
	}
}
