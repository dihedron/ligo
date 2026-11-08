//go:build integration

package bindings

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/metrics/gauges"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// gauge reads a database gauge as a scrape does; 0 if it has no such series.
func gauge(t *testing.T, s *Service, family, label, value string) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(&gauges.DB{Pool: s.DB, Logger: slog.New(slog.DiscardHandler), Timeout: 5 * time.Second})
	got, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == label && l.GetValue() == value {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}

// lockable tries each row lock without waiting; an error means an open
// transaction holds that row.
func lockable(ctx context.Context, o *pgxpool.Pool, queries map[string][]any) map[string]error {
	out := map[string]error{}
	for sql, args := range queries {
		out[sql] = pgx.BeginFunc(ctx, o, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, sql+" FOR UPDATE NOWAIT", args...)
			if err != nil {
				return err
			}
			rows.Close()
			return rows.Err()
		})
	}
	return out
}

// TestAC23: while an approval waits for its plugin call, it holds no row
// lock: every row it will write can be locked at once, and another request
// can be approved and applied meanwhile (§4.3).
func TestAC23(t *testing.T) {
	s, o, w, p := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	updated := "dd-u-" + w.suffix
	active(t, s, o, dcOp, updated, w.dcSrc, w.dcShared, "read", "", dcApp)
	update, err := s.Update(ctx, dcOp, updated, body(updated, w.dcSrc, w.dcShared, "write", `"expectedRevision":1`))
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.Create(ctx, cloudOp, body("fin-01-payments-c-"+w.suffix, w.cloudSrc, w.cloudTgt, "read"))
	if err != nil {
		t.Fatal(err)
	}
	bystander := source(t, o, w, "b")
	unrelated, err := s.Create(ctx, dcOp, body("dd-o-"+w.suffix, bystander, w.dcShared, "read"))
	if err != nil {
		t.Fatal(err)
	}

	for label, tc := range map[string]*changerequests.Request{"CREATE": created, "UPDATE": update} {
		t.Run(label, func(t *testing.T) {
			var calls atomic.Int32
			var probed bool
			s.Validate = func(c context.Context, req *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error) {
				if calls.Add(1) == 1 { // the slow call: the first of this approval
					probed = true
					for sql, err := range lockable(ctx, o, map[string][]any{
						"SELECT 1 FROM change_requests WHERE id = $1":                                                      {tc.ID},
						"SELECT 1 FROM change_request_sides WHERE change_request_id = $1":                                  {tc.ID},
						"SELECT 1 FROM bindings WHERE name = $1":                                                           {tc.ResourceName},
						"SELECT 1 FROM sources WHERE name = ANY($1)":                                                       {[]string{w.dcSrc, w.cloudSrc}},
						"SELECT 1 FROM targets WHERE name = ANY($1)":                                                       {[]string{w.dcShared, w.cloudTgt}},
						"SELECT 1 FROM target_access_levels l JOIN targets t ON t.id = l.target_id WHERE t.name = ANY($1)": {[]string{w.dcShared, w.cloudTgt}},
						"SELECT 1 FROM system_settings":                                                                    {},
					}) {
						if err != nil {
							t.Errorf("locked during the plugin call: %s: %v", sql, err)
						}
					}
				}
				return p.validate(c, req)
			}
			defer func() { s.Validate = p.validate }()
			approver := cloudLead
			if tc == update {
				approver = dcApp
			}
			if _, err := s.Requests.Approve(ctx, approver, tc.ID, tc.PayloadSHA256, "", "ok"); err != nil {
				t.Fatal(err)
			}
			if !probed {
				t.Error("the approval did not call the plugin")
			}
			if st := status(t, o, tc.ID); st != "APPLIED" {
				t.Errorf("status %s", st)
			}
		})
	}

	// another request is decided while one approval waits for its plugin
	var nested atomic.Bool
	hold := func(c context.Context, req *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error) {
		if nested.CompareAndSwap(false, true) {
			if _, err := s.Requests.Approve(ctx, dcApp, unrelated.ID, unrelated.PayloadSHA256, "", "ok"); err != nil {
				t.Errorf("the other request: %v", err)
			}
		}
		return p.validate(c, req)
	}
	waiting := "dd-w-" + w.suffix
	r, err := s.Create(ctx, dcOp, body(waiting, source(t, o, w, "w"), w.dcShared, "read"))
	if err != nil {
		t.Fatal(err)
	}
	s.Validate = hold
	defer func() { s.Validate = p.validate }()
	if _, err := s.Requests.Approve(ctx, dcApp, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if st := status(t, o, unrelated.ID); st != "APPLIED" {
		t.Errorf("the other request: %s", st)
	}
}

// TestAC54: a delegated request across jurisdictions decides only the delegated
// side; nothing is provisioned until the people of the others approve.
func TestAC54(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "fin-01-payments-a-" + w.suffix
	r, err := s.Create(ctx, automation, body(name, w.cloudSrc, w.ledger, "read", `"approvalReference":"CHG0012345"`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || sides(r) != "TARGET=DELEGATED,SOURCE=HUMAN,PARTY:security=HUMAN" {
		t.Fatalf("request %s %s", r.Status, sides(r))
	}
	provisioned := func() int {
		var n int
		if err := o.QueryRow(ctx, "select count(*) from bindings where name = $1", name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if provisioned() != 0 {
		t.Fatal("provisioned on the delegated side alone")
	}
	approve(t, s, r, sec)
	if provisioned() != 0 {
		t.Fatal("provisioned before the tenancy lead approved")
	}
	approve(t, s, r, cloudLead)
	if phase, _, _, _, _ := bindingRow(t, o, name); phase != "PROVISIONING" {
		t.Errorf("phase %s", phase)
	}
}

// TestAC55: break_glass on one side only is refused; with it on every side
// the change applies, and is reverted at expiry unless a different approver
// ratifies each side: one side ratified is not enough.
func TestAC55(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	s.Requests.Policy.BreakGlassPolicies = append(s.Requests.Policy.BreakGlassPolicies,
		governance.BreakGlassPolicy{Jurisdictions: []string{"sec/infosec"}, DefaultTTL: time.Hour, MaxTTL: time.Hour, MaxOpen: 5})
	rescuer := caller("rita", role(config.RoleBreakGlass, "cloud/fin-01/*", "dc/corp-prod/*", "sec/infosec"))
	name := "fin-01-payments-p-" + w.suffix
	create := func(n string) []byte {
		return emergency("CREATE", `"binding":`+string(body(n, w.cloudSrc, w.ledger, "read"))+`,`, "")
	}
	if _, err := s.BreakGlass(ctx, livia, create(name)); slug(err) != "forbidden" {
		t.Errorf("break_glass on one jurisdiction: %v", err)
	}

	bg, err := s.BreakGlass(ctx, rescuer, create(name))
	if err != nil {
		t.Fatal(err)
	}
	if bg.Status != "APPLIED" {
		t.Fatalf("status %s", bg.Status)
	}
	if _, err := s.Ratify(ctx, ledgerApp, bg.ID, "TARGET", "confirmed"); err != nil {
		t.Fatal(err)
	}
	if cr, _ := breakGlassOf(t, o, name); cr == nil {
		t.Fatal("one ratified side closed the change")
	}
	expireBreakGlass(t, o, name)
	if err := s.RevertExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if r, n := revertOf(t, o, bg.ID); n == 0 || r.op != "DELETE" || r.status != "APPLIED" {
		t.Fatalf("one side ratified, revert %+v (%d)", r, n)
	}
	if phase, _, _, _, _ := bindingRow(t, o, name); phase != "DELETING" {
		t.Errorf("phase %s", phase)
	}
	if _, err := o.Exec(ctx, "delete from bindings where name = $1", name); err != nil { // the delete workflow's end
		t.Fatal(err)
	}

	kept := "fin-01-payments-q-" + w.suffix
	bg, err = s.BreakGlass(ctx, rescuer, create(kept))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ratify(ctx, marco, bg.ID, "TARGET", "confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ratify(ctx, marco, bg.ID, "PARTY:security", "confirmed"); slug(err) != "distinct-approver-required" {
		t.Errorf("one person ratifies two sides: %v", err)
	}
	if _, err := s.Ratify(ctx, sec, bg.ID, "PARTY:security", "confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ratify(ctx, cloudLead, bg.ID, "SOURCE", "confirmed"); err != nil {
		t.Fatal(err)
	}
	if cr, _ := breakGlassOf(t, o, kept); cr != nil {
		t.Errorf("every side ratified, still open: %v", cr)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", kept); err != nil {
		t.Fatal(err)
	}
	if err := s.RevertExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if r, n := revertOf(t, o, bg.ID); n != 0 {
		t.Errorf("ratified, yet reverted: %+v (%d)", r, n)
	}
}

// TestAC58: on a binding a new deny rule covers, a raise is refused while a
// downgrade and the revocation are still accepted and applied (ADR-14).
func TestAC58(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "fin-01-payments-v-" + w.suffix
	active(t, s, o, cloudOp, name, w.cloudSrc, w.ledger, "write", "", ledgerApp, cloudLead, sec)
	for i, rule := range s.Requests.Policy.Interconnects.Rules {
		if rule.Name == "cloud-to-dc" {
			s.Requests.Policy.Interconnects.Rules[i].Action = "deny"
		}
	}
	r, err := s.Update(ctx, ledgerOp, name, body(name, w.cloudSrc, w.ledger, "read", `"expectedRevision":1`))
	if err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if r.Consent != changerequests.ConsentAny {
		t.Errorf("downgrade consent %s", r.Consent)
	}
	approve(t, s, r, ledgerApp)
	if st := status(t, o, r.ID); st != "APPLIED" {
		t.Fatalf("downgrade %s", st)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, ledgerOp, name, body(name, w.cloudSrc, w.ledger, "write", `"expectedRevision":2`)); slug(err) != "interconnect-denied" {
		t.Errorf("raise: %v", err)
	}
	d, err := s.Delete(ctx, ledgerOp, name, 2, "", nil)
	if err != nil {
		t.Fatalf("revocation: %v", err)
	}
	approve(t, s, d, ledgerApp)
	if phase, _, _, _, _ := bindingRow(t, o, name); phase != "DELETING" {
		t.Errorf("phase %s", phase)
	}
}

// TestAC66: nothing new binds to a deprecated target, and no binding moves
// to a deprecated level; an existing binding can still change otherwise.
func TestAC66(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "dd-" + w.suffix
	active(t, s, o, dcOp, name, w.dcSrc, w.dcShared, "read", "", dcApp)
	if _, err := o.Exec(ctx, `update target_access_levels set state = 'DEPRECATED' where name = 'write'
		and target_id = (select id from targets where name = $1)`, w.dcShared); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.dcShared, "write", `"expectedRevision":1`)); slug(err) != "resource-deprecated" {
		t.Errorf("upgrade to a deprecated level: %v", err)
	}
	if _, err := o.Exec(ctx, "update targets set state = 'DEPRECATED' where name = $1", w.dcShared); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, dcOp, body("dd-n-"+w.suffix, source(t, o, w, "n"), w.dcShared, "read")); slug(err) != "resource-deprecated" {
		t.Errorf("new binding to a deprecated target: %v", err)
	}
	r, err := s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.dcShared, "read", `"expectedRevision":1`, `"parameters":{"connectionLimit":5}`))
	if err != nil {
		t.Fatalf("a change at the current level: %v", err)
	}
	approve(t, s, r, dcApp)
	if st := status(t, o, r.ID); st != "APPLIED" {
		t.Errorf("a change at the current level: %s", st)
	}
}

// TestAC70: the platform owner may revoke a binding on a target it does not
// own, but neither create nor raise one (ADR-13 rule 4).
func TestAC70(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "fin-01-payments-o-" + w.suffix
	active(t, s, o, cloudOp, name, w.cloudSrc, w.dcShared, "read", "", dcApp, cloudLead, sec)
	if _, err := s.Create(ctx, dcOp, body("fin-01-payments-n-"+w.suffix, w.cloudSrc, w.ledger, "read")); slug(err) != "forbidden" {
		t.Errorf("create on a target the platform owner does not own: %v", err)
	}
	named := "fin-01-payments-l-" + w.suffix
	active(t, s, o, cloudOp, named, w.cloudSrc, w.ledger, "read", "", ledgerApp, cloudLead, sec)
	if _, err := s.Update(ctx, dcOp, named, body(named, w.cloudSrc, w.ledger, "write", `"expectedRevision":1`)); slug(err) != "forbidden" {
		t.Errorf("raise: %v", err)
	}
	r, err := s.Delete(ctx, dcOp, named, 1, "", nil)
	if err != nil {
		t.Fatalf("revocation: %v", err)
	}
	approve(t, s, r, dcApp)
	if phase, _, _, _, _ := bindingRow(t, o, named); phase != "DELETING" {
		t.Errorf("phase %s", phase)
	}
}

// TestAC86: a binding keeps the principal name it was created with when the
// platform's prefix changes, through updates and its deletion; new bindings
// take the new prefix; the column cannot be changed (INV-08).
func TestAC86(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	b, c := "dd-b-"+w.suffix, "dd-c-"+w.suffix
	active(t, s, o, dcOp, b, w.dcSrc, w.dcShared, "read", "", dcApp)
	_, _, kept, _, _ := bindingRow(t, o, b)
	if len(kept) != 20 || kept[:4] != "svc_" {
		t.Fatalf("principal %s", kept)
	}
	p := s.Rules.Platforms["oracle-prod"]
	p.PrincipalPrefix = "app_" // a restart with the new configuration
	s.Rules.Platforms["oracle-prod"] = p

	r, err := s.Update(ctx, dcOp, b, body(b, w.dcSrc, w.dcShared, "write", `"expectedRevision":1`))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, dcApp)
	if _, _, principal, _, revision := bindingRow(t, o, b); principal != kept || revision != 2 {
		t.Errorf("after an update: %s r%d, want %s", principal, revision, kept)
	}
	n, err := s.Create(ctx, dcOp, body(c, source(t, o, w, "c"), w.dcShared, "read"))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, n, dcApp)
	if _, _, principal, _, _ := bindingRow(t, o, c); len(principal) != 20 || principal[:4] != "app_" {
		t.Errorf("new binding: %s", principal)
	}
	if _, err := s.DB.Exec(ctx, "update bindings set derived_principal_name = 'app_ty7bsxjkraerelw2' where name = $1", b); err == nil {
		t.Error("the principal name was updated")
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", b); err != nil {
		t.Fatal(err)
	}
	d, err := s.Delete(ctx, dcOp, b, 2, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, d, dcApp)
	if phase, _, principal, _, _ := bindingRow(t, o, b); phase != "DELETING" || principal != kept {
		t.Errorf("deleting: %s %s, want %s", phase, principal, kept)
	}
}

// TestAC05c: approving a DELETE applies it without calling any plugin.
func TestAC05c(t *testing.T) {
	s, o, w, p := setup(t)
	ctx := context.Background()
	name := "dd-" + w.suffix
	active(t, s, o, dcOp, name, w.dcSrc, w.dcShared, "read", "", dcApp)
	var calls atomic.Int32
	s.Validate = func(c context.Context, req *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error) {
		calls.Add(1)
		return p.validate(c, req)
	}
	r, err := s.Delete(ctx, dcOp, name, 1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" {
		t.Fatalf("status %s", r.Status)
	}
	approve(t, s, r, dcApp)
	if phase, _, _, _, _ := bindingRow(t, o, name); phase != "DELETING" {
		t.Errorf("phase %s", phase)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d plugin calls", n)
	}
}

// TestAC25: a side filed under a stricter policy still needs an approver
// other than the requester once the jurisdiction stops requiring approval.
func TestAC25(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	both := caller("mia", role(config.RoleOperator, "dc/corp-prod"), role(config.RoleApprover, "dc/corp-prod"))
	r, err := s.Create(ctx, both, body("dd-"+w.suffix, w.dcSrc, w.dcShared, "read"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || sides(r) != "TARGET=HUMAN" {
		t.Fatalf("request %s %s", r.Status, sides(r))
	}
	cfg := example(t)
	cfg.Authorization.Approval.RequiredJurisdictions = nil
	s.Requests.Policy = cfg.Policy() // the restart with the weaker policy
	if s.Requests.Policy.ApprovalRequired("dc/corp-prod") {
		t.Fatal("the policy still requires approval")
	}
	if _, err := s.Requests.Approve(ctx, both, r.ID, r.PayloadSHA256, "", "ok"); slug(err) != "four-eyes-violation" {
		t.Errorf("the requester approves: %v", err)
	}
	if st := status(t, o, r.ID); st != "PENDING" {
		t.Fatalf("status %s", st)
	}
	approve(t, s, r, dcApp)
	if st := status(t, o, r.ID); st != "APPLIED" {
		t.Errorf("status %s", st)
	}
}

// TestAC76Backlog: 50 narrowing rows, one of them busy, and 10 of a changed
// target, with maintenance on: only the narrowing runs, the busy one is
// deferred, the depth gauge shows what is left; all drain afterwards.
func TestAC76Backlog(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	narrowed, changed := make([]string, 50), make([]string, 10)
	queued := func(names []string, label string, priority int) {
		for i := range names {
			n := fmt.Sprintf("%s%d", label, i)
			names[i] = "dd-" + n + "-" + w.suffix
			active(t, s, o, dcOp, names[i], source(t, o, w, n), w.dcShared, "read", "", dcApp)
			enqueue(t, o, names[i], "", priority)
		}
	}
	depth0, depth1 := gauge(t, s, "ligo_propagation_queue_depth", "priority", "0"), gauge(t, s, "ligo_propagation_queue_depth", "priority", "1")
	queued(narrowed, "n", 0)
	queued(changed, "c", 1)
	busy := narrowed[0]
	if _, err := o.Exec(ctx, "update bindings set phase = 'PROVISIONING' where name = $1", busy); err != nil {
		t.Fatal(err)
	}
	if d := gauge(t, s, "ligo_propagation_queue_depth", "priority", "0"); d != depth0+50 {
		t.Errorf("depth 0 before: %v, want %v", d, depth0+50)
	}
	if _, err := o.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = o.Exec(context.Background(), "update system_settings set maintenance_mode = false") })
	p := &Propagator{Service: s, MaxConcurrent: 1000}
	if _, err := p.Propagate(ctx); err != nil {
		t.Log(err)
	}
	if _, err := o.Exec(ctx, "update system_settings set maintenance_mode = false"); err != nil {
		t.Fatal(err)
	}
	for _, name := range narrowed[1:] {
		if r := propagation(t, o, name); r.revision != 2 || r.queued {
			t.Errorf("narrowing during maintenance %s %+v", name, r)
		}
	}
	for _, name := range changed {
		if r := propagation(t, o, name); r.revision != 1 || !r.queued {
			t.Errorf("priority 1 during maintenance %s %+v", name, r)
		}
	}
	if r := propagation(t, o, busy); r.revision != 1 || !r.queued {
		t.Errorf("busy %+v", r)
	}
	if n, _ := audited(t, o, busy, "PROPAGATION_DEFERRED"); n != 1 {
		t.Errorf("PROPAGATION_DEFERRED %d", n)
	}
	if d := gauge(t, s, "ligo_propagation_queue_depth", "priority", "0"); d != depth0+1 {
		t.Errorf("depth 0 after: %v, want %v", d, depth0+1)
	}
	if d := gauge(t, s, "ligo_propagation_queue_depth", "priority", "1"); d != depth1+10 {
		t.Errorf("depth 1 after: %v, want %v", d, depth1+10)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = any($1)", narrowed); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Propagate(ctx); err != nil {
		t.Log(err)
	}
	for _, name := range append([]string{busy}, changed...) {
		if r := propagation(t, o, name); r.revision != 2 || r.queued {
			t.Errorf("%s after the drain %+v", name, r)
		}
	}
	if d := gauge(t, s, "ligo_propagation_queue_depth", "priority", "1"); d != depth1 {
		t.Errorf("depth 1 drained: %v, want %v", d, depth1)
	}
}
