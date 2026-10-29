//go:build integration

package changerequests

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/authz"
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

// fake is a resource whose revalidation and apply the test controls.
type fake struct {
	revalidate error
	payload    json.RawMessage // returned by Revalidate; nil: the stored one
	apply      error
	applied    int
	after      []uuid.UUID // Applied calls, after commit
}

func (f *fake) Applied(_ context.Context, r *Request) { f.after = append(f.after, r.ID) }

func (f *fake) Revalidate(_ context.Context, r *Request) (json.RawMessage, error) {
	if f.payload != nil {
		return f.payload, f.revalidate
	}
	return r.Payload, f.revalidate
}

func (f *fake) Apply(context.Context, pgx.Tx, *Request) ([]audit.Entry, error) {
	if f.apply != nil {
		return nil, f.apply
	}
	f.applied++
	return []audit.Entry{{Action: "SOURCE_TEST_APPLIED"}}, nil
}

func setup(t *testing.T) (*Service, *fake, *pgxpool.Pool) {
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
	f := &fake{}
	return &Service{DB: pools.App, Policy: policy, TTL: 72 * time.Hour, Resources: map[string]Resource{"SOURCE": f}}, f, owner
}

var (
	alice = Caller{Principal: authz.Principal{Name: "alice"}, Grants: authz.Grants{grant(config.RoleOperator, "cloud/*", "dc/*")}}
	bob   = Caller{Principal: authz.Principal{Name: "bob"}, Grants: authz.Grants{grant(config.RoleApprover, "dc/*")}}
	eve   = Caller{Principal: authz.Principal{Name: "eve"}, Grants: authz.Grants{grant(config.RoleViewer, "dc/*")}}
)

// newSource files a SOURCE CREATE in scope as alice.
func newSource(t *testing.T, s *Service, owner *pgxpool.Pool, scope string) *Request {
	t.Helper()
	r := &Request{ResourceType: "SOURCE", ResourceName: "test-" + uuid.NewV7().String()[24:], Operation: "CREATE",
		Consent: ConsentAll, OwnerScope: scope, Payload: json.RawMessage(`{"kind":"Source","name":"x"}`)}
	if err := s.Create(context.Background(), alice, r, []Candidate{{Side: "OWNER", Scope: scope}}, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from change_requests where id = $1", r.ID)
	})
	return r
}

func statusOf(t *testing.T, owner *pgxpool.Pool, id uuid.UUID) (string, string) {
	t.Helper()
	var status, decidedBy string
	if err := owner.QueryRow(context.Background(), "select status, coalesce(decided_by, '') from change_requests where id = $1", id).Scan(&status, &decidedBy); err != nil {
		t.Fatal(err)
	}
	return status, decidedBy
}

func actions(t *testing.T, owner *pgxpool.Pool, id uuid.UUID) []string {
	t.Helper()
	rows, err := owner.Query(context.Background(), "select action from audit_log where change_request_id = $1 order by id", id)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAutoApplied: a request whose sides are all decided at creation is
// applied in the transaction that creates it (§7.2.3 rule 5).
func TestAutoApplied(t *testing.T) {
	s, f, owner := setup(t)
	r := newSource(t, s, owner, payments)
	if st, by := statusOf(t, owner, r.ID); st != "APPLIED" || by != "system:auto-approve" || f.applied != 1 {
		t.Errorf("status %s by %s, applied %d", st, by, f.applied)
	}
	if got := actions(t, owner, r.ID); !equal(got, []string{"CR_CREATED", "CR_SIDE_APPROVED", "CR_APPROVED", "SOURCE_TEST_APPLIED"}) {
		t.Errorf("audit %v", got)
	}
	if len(f.after) != 1 || f.after[0] != r.ID {
		t.Errorf("Applied after commit: %v", f.after)
	}
}

// TestAC04AC05: in an approval-required scope the requester cannot approve,
// a stale hash leaves the request pending, and another approver applies it.
func TestAC04AC05(t *testing.T) {
	s, f, owner := setup(t)
	ctx := context.Background()
	r := newSource(t, s, owner, ledger)
	if st, _ := statusOf(t, owner, r.ID); st != "PENDING" || f.applied != 0 {
		t.Fatalf("status %s, applied %d", st, f.applied)
	}
	if _, err := s.Approve(ctx, alice, r.ID, r.PayloadSHA256, "", "ok"); status(err) != "four-eyes-violation" {
		t.Errorf("requester approves: %v", err)
	}
	if _, err := s.Approve(ctx, eve, r.ID, r.PayloadSHA256, "", "ok"); status(err) != "forbidden" {
		t.Errorf("viewer approves: %v", err)
	}
	if _, err := s.Approve(ctx, bob, r.ID, "0000000000000000000000000000000000000000000000000000000000000000", "", "ok"); status(err) != "payload-mismatch" {
		t.Errorf("stale hash: %v", err)
	}
	if st, _ := statusOf(t, owner, r.ID); st != "PENDING" {
		t.Fatalf("after a stale hash: %s", st)
	}
	if _, err := s.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if st, by := statusOf(t, owner, r.ID); st != "APPLIED" || by != "bob" || f.applied != 1 {
		t.Errorf("status %s by %s, applied %d", st, by, f.applied)
	}
	if len(f.after) != 1 { // not while pending, once when applied
		t.Errorf("Applied calls %v", f.after)
	}
	if got := actions(t, owner, r.ID); !equal(got, []string{"CR_CREATED", "CR_SIDE_APPROVED", "CR_APPROVED", "SOURCE_TEST_APPLIED"}) {
		t.Errorf("audit %v", got)
	}
	if _, err := s.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "again"); status(err) != "change-request-not-pending" {
		t.Errorf("second approval: %v", err)
	}
}

func TestDeclineAndWithdraw(t *testing.T) {
	s, _, owner := setup(t)
	ctx := context.Background()
	r := newSource(t, s, owner, ledger)
	if _, err := s.Decline(ctx, bob, r.ID, "", "no"); err != nil {
		t.Fatal(err)
	}
	if st, by := statusOf(t, owner, r.ID); st != "REJECTED" || by != "bob" {
		t.Errorf("declined: %s by %s", st, by)
	}
	w := newSource(t, s, owner, ledger)
	if err := s.Withdraw(ctx, bob, w.ID, "mine?"); status(err) != "forbidden" {
		t.Errorf("withdrawn by another: %v", err)
	}
	if err := s.Withdraw(ctx, alice, w.ID, "not needed"); err != nil {
		t.Fatal(err)
	}
	if st, _ := statusOf(t, owner, w.ID); st != "WITHDRAWN" {
		t.Errorf("withdrawn: %s", st)
	}
	if err := s.Withdraw(ctx, alice, w.ID, "again"); status(err) != "change-request-not-pending" {
		t.Errorf("withdrawn twice: %v", err)
	}
	if got := actions(t, owner, w.ID); !equal(got, []string{"CR_CREATED", "CR_WITHDRAWN"}) {
		t.Errorf("audit %v", got)
	}
}

// TestApproveFailures: a failed re-validation, a normalization drift and a
// failed apply leave the request FAILED_TO_APPLY (§7.2.3 approval, §6.2.1).
func TestApproveFailures(t *testing.T) {
	s, f, owner := setup(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		setup func()
		slug  string
	}{
		"revalidation": {func() { f.revalidate = errors.New("access level outside the bounds") }, "validation-failed"},
		"drift":        {func() { f.payload = json.RawMessage(`{"kind":"Source","name":"y"}`) }, "normalization-drift"},
		"apply":        {func() { f.apply = &Error{Status: 409, Slug: "revision-conflict"} }, "revision-conflict"},
	} {
		t.Run(name, func(t *testing.T) {
			*f = fake{}
			r := newSource(t, s, owner, ledger)
			tc.setup()
			if _, err := s.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); status(err) != tc.slug {
				t.Errorf("err = %v, want %s", err, tc.slug)
			}
			if st, _ := statusOf(t, owner, r.ID); st != "FAILED_TO_APPLY" {
				t.Errorf("status %s", st)
			}
			if got := actions(t, owner, r.ID); got[len(got)-1] != "CR_APPLY_FAILED" {
				t.Errorf("audit %v", got)
			}
		})
	}
}

// newBinding files a BINDING CREATE as alice with a SOURCE side in payments
// (decided automatically) and a TARGET side in ledger (pending).
func newBinding(t *testing.T, s *Service, owner *pgxpool.Pool) *Request {
	t.Helper()
	r := &Request{ResourceType: "BINDING", ResourceName: "test-" + uuid.NewV7().String()[24:], Operation: "CREATE",
		Consent: ConsentAll, Zone: "prod", SourceScope: payments, TargetScope: ledger, PlatformScope: "dc/corp-prod",
		InterconnectRule: "cloud-to-dc", DistinctApprovers: false, Payload: json.RawMessage(`{"kind":"Binding"}`)}
	err := s.Create(context.Background(), alice, r, []Candidate{{Side: "SOURCE", Scope: payments}, {Side: "TARGET", Scope: ledger}}, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), "delete from change_requests where id = $1", r.ID) })
	return r
}

// TestInterconnectRule: a binding request keeps its rule and the rule's
// distinct_approvers (ADR-14 rule 4).
func TestInterconnectRule(t *testing.T) {
	s, _, owner := setup(t)
	s.Resources["BINDING"] = &fake{}
	r := newBinding(t, s, owner)
	var rule string
	var distinct bool
	if err := owner.QueryRow(context.Background(), "select interconnect_rule, distinct_approvers_required from change_requests where id = $1", r.ID).
		Scan(&rule, &distinct); err != nil || rule != "cloud-to-dc" || distinct {
		t.Errorf("rule %q distinct %t (%v)", rule, distinct, err)
	}
}

// TestAC52: a side decided automatically that the policy now in force
// would leave to a person fails the request at apply (ADR-14 rule 5).
func TestAC52(t *testing.T) {
	s, f, owner := setup(t)
	s.Resources["BINDING"] = f
	r := newBinding(t, s, owner)
	s.Policy = &governance.Policy{RequiredScopes: []string{"dc/corp-prod/*", "cloud/*"}} // tightened
	if _, err := s.Approve(context.Background(), bob, r.ID, r.PayloadSHA256, "", "ok"); status(err) != "governance-policy-changed" {
		t.Fatalf("err = %v", err)
	}
	if st, _ := statusOf(t, owner, r.ID); st != "FAILED_TO_APPLY" || f.applied != 0 {
		t.Errorf("status %s, applied %d", st, f.applied)
	}
}

// TestBusy: an approval that finds the binding busy is rolled back, side
// decision included; a request complete at creation fails instead (§6.2.2).
func TestBusy(t *testing.T) {
	s, f, owner := setup(t)
	ctx := context.Background()
	s.Resources["BINDING"] = f
	f.apply = &Error{Status: 409, Slug: "binding-busy"}
	r := newBinding(t, s, owner)
	if _, err := s.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); status(err) != "binding-busy" {
		t.Fatalf("err = %v", err)
	}
	var pending int
	if err := owner.QueryRow(ctx, "select count(*) from change_request_sides where change_request_id = $1 and decision is null", r.ID).Scan(&pending); err != nil || pending != 1 {
		t.Errorf("%d undecided sides (%v)", pending, err)
	}
	if st, _ := statusOf(t, owner, r.ID); st != "PENDING" {
		t.Errorf("status %s", st)
	}
	a := &Request{ResourceType: "SOURCE", ResourceName: "test-" + uuid.NewV7().String()[24:], Operation: "CREATE",
		Consent: ConsentAll, OwnerScope: payments, Payload: json.RawMessage(`{"kind":"Source"}`)}
	err := s.Create(ctx, alice, a, []Candidate{{Side: "OWNER", Scope: payments}}, "") // complete at creation
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), "delete from change_requests where id = $1", a.ID) })
	if status(err) != "binding-busy" {
		t.Errorf("busy at creation: %v", err)
	}
	if st, by := statusOf(t, owner, a.ID); st != "FAILED_TO_APPLY" || by != "system:auto-approve" {
		t.Errorf("request complete at creation: %s by %s", st, by)
	}
}
