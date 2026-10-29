//go:build integration

package workflows

import (
	"context"
	"testing"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/jackc/pgx/v5"
)

func (v *env) sweep(t *testing.T) {
	t.Helper()
	ran, err := (&Sweeper{Engine: v.engine, Stale: time.Minute}).Sweep(context.Background())
	if err != nil || !ran {
		t.Fatalf("sweep: ran %t, %v", ran, err)
	}
}

func (v *env) stale(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := v.owner.Exec(context.Background(), "update bindings set last_transition_at = now() - interval '2 minutes' where id = $1", id); err != nil {
		t.Fatal(err)
	}
}

func (v *env) waitPhase(t *testing.T, id uuid.UUID, phase string) row {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		r := v.row(t, id)
		if r.phase == phase || time.Now().After(deadline) {
			return r
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestAC19: a binding committed PROVISIONING whose workflow never started
// (the process died between the commit and the start) is started by the
// sweeper once stale, and converges; a fresh one is left alone.
func TestAC19(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	stale, fresh := v.binding(t), v.binding(t)
	v.stale(t, stale)
	v.sweep(t)
	if r := v.waitPhase(t, stale, "ACTIVE"); r.phase != "ACTIVE" {
		t.Errorf("stale binding %+v", r)
	}
	time.Sleep(300 * time.Millisecond)
	if r := v.row(t, fresh); r.phase != "PROVISIONING" || r.step != "INIT" {
		t.Errorf("fresh binding %+v", r)
	}
}

// TestSweepTerminated: a workflow that ended without marking its binding
// (cancelled here) leaves it FAILED, fenced, with the sweeper's message.
func TestSweepTerminated(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	v.fake.storeBlock = make(chan struct{}) // never closed
	id := v.binding(t)
	if _, err := v.engine.Start(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := v.waitStep(t, id, "ensureSecretStore"); r.step != "ensureSecretStore" {
		t.Fatalf("binding %+v", r)
	}
	var wf string
	if err := v.owner.QueryRow(context.Background(), "select workflow_id from bindings where id = $1", id).Scan(&wf); err != nil {
		t.Fatal(err)
	}
	if err := dbos.CancelWorkflow(v.engine.DBOS, wf); err != nil {
		t.Fatal(err)
	}
	v.stale(t, id)
	v.sweep(t)
	if r := v.row(t, id); r.phase != "FAILED" || r.message != "workflow terminated unexpectedly" || v.audited(t, id, "PROVISION_FAILURE") != 1 {
		t.Errorf("binding %+v", r)
	}
}

func (v *env) waitStep(t *testing.T, id uuid.UUID, step string) row {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		r := v.row(t, id)
		if r.step == step || time.Now().After(deadline) {
			return r
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// request inserts a change request and its sides, removed at the end of
// the test.
func (v *env) request(t *testing.T, sql string, args []any, sides ...string) {
	t.Helper()
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, v.owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		for _, s := range sides {
			if _, err := tx.Exec(ctx, `insert into change_request_sides (change_request_id, side, scope, approval_required, basis, requested_by, cr_kind)
				values ($1, $2, 'dc/corp-prod', true, 'HUMAN', 'alice', 'STANDARD')`, args[0], s); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = v.owner.Exec(context.Background(), "delete from change_requests where id = $1", args[0])
	})
}

func (v *env) status(t *testing.T, cr uuid.UUID) (string, string) {
	t.Helper()
	var status, applyError string
	if err := v.owner.QueryRow(context.Background(), "select status, coalesce(apply_error, '') from change_requests where id = $1", cr).Scan(&status, &applyError); err != nil {
		t.Fatal(err)
	}
	return status, applyError
}

// TestSweepRequests: a pending request past its expiry is EXPIRED; a
// binding CREATE whose inline source's request ended unapplied fails
// (§6.3).
func TestSweepRequests(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	expired, source, dependent := uuid.NewV7(), uuid.NewV7(), uuid.NewV7()
	x := expired.String()[24:]
	v.request(t, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, owner_scope, policy_sha256,
		distinct_approvers_required, payload, payload_sha256, requested_by, expires_at)
		values ($1, 'SOURCE', $2, 'CREATE', 'STANDARD', 'ALL', 'dc/corp-prod', repeat('a', 64), true, '{}', repeat('b', 64), 'alice', now() - interval '1 hour')`,
		[]any{expired, "x-" + x}, "OWNER")
	v.request(t, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, owner_scope, policy_sha256,
		distinct_approvers_required, payload, payload_sha256, status, requested_by, expires_at)
		values ($1, 'SOURCE', $2, 'CREATE', 'STANDARD', 'ALL', 'dc/corp-prod', repeat('a', 64), true, '{}', repeat('b', 64), 'WITHDRAWN', 'alice', now() + interval '1 day')`,
		[]any{source, "s-" + x}, "OWNER")
	v.request(t, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, zone, source_scope, target_scope,
		platform_scope, policy_sha256, distinct_approvers_required, payload, payload_sha256, depends_on_cr_id, requested_by, expires_at)
		values ($1, 'BINDING', $2, 'CREATE', 'STANDARD', 'ALL', 'prod', 'dc/corp-prod', 'dc/corp-prod', 'dc/corp-prod', repeat('a', 64), true,
		'{}', repeat('b', 64), $3, 'alice', now() + interval '1 day')`, []any{dependent, "b-" + x, source}, "TARGET")
	v.sweep(t)
	if st, _ := v.status(t, expired); st != "EXPIRED" {
		t.Errorf("expired request: %s", st)
	}
	if st, applyError := v.status(t, dependent); st != "FAILED_TO_APPLY" || applyError != "inline source not registered" {
		t.Errorf("dependent request: %s (%s)", st, applyError)
	}
	var n int
	if err := v.owner.QueryRow(context.Background(), `select count(*) from audit_log where change_request_id in ($1, $2)
		and action in ('CR_EXPIRED', 'CR_DEPENDENCY_FAILED')`, expired, dependent).Scan(&n); err != nil || n != 2 {
		t.Errorf("audit %d (%v)", n, err)
	}
}

// TestSweepSingleton: while another replica holds the sweeper's lock, a
// sweep does nothing (§6.3).
func TestSweepSingleton(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	ctx := context.Background()
	conn, err := v.engine.DB.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('ligo_sweeper'))"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtext('ligo_sweeper'))") }()
	ran, err := (&Sweeper{Engine: v.engine}).Sweep(ctx)
	if err != nil || ran {
		t.Errorf("sweep under another replica's lock: ran %t, %v", ran, err)
	}
}

// TestRunLoops: the singletons run their pass on every tick until their
// context ends; the sweeper's expiry and break-glass duties run with a
// bindings service.
func TestRunLoops(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	bs := &bindings.Service{DB: v.engine.DB, Requests: &changerequests.Service{DB: v.engine.DB, Policy: &governance.Policy{}}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{}, 2)
	go func() {
		(&Sweeper{Engine: v.engine, Interval: 20 * time.Millisecond, Bindings: bs}).Run(ctx)
		done <- struct{}{}
	}()
	go func() {
		(&Reconciler{Engine: v.engine, Interval: 20 * time.Millisecond, Jitter: time.Millisecond, MaxConcurrent: 1}).Run(ctx)
		done <- struct{}{}
	}()
	<-done
	<-done
	// a pass cancelled mid-query closes its connection; its lock goes once the server notices
	var ran bool
	var err error
	for deadline := time.Now().Add(2 * time.Second); !ran && err == nil && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		ran, err = (&Sweeper{Engine: v.engine, Bindings: bs}).Sweep(context.Background())
	}
	if err != nil || !ran {
		t.Errorf("sweep with expiry: %t %v", ran, err)
	}
}

// TestRevertOutcome: the attempt of a revision a SYSTEM_REVERT started
// audits BREAK_GLASS_REVERTED when it ends (§6.3, INV-16); other attempts
// do not. A binding that is not FAILED is not retried.
func TestRevertOutcome(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	ctx := context.Background()
	id, plain := v.binding(t), v.binding(t)
	var name string
	if err := v.owner.QueryRow(ctx, "select name from bindings where id = $1", id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	bg, revert := uuid.NewV7(), uuid.NewV7()
	err := pgx.BeginFunc(ctx, v.owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent, zone,
			source_scope, target_scope, platform_scope, policy_sha256, distinct_approvers_required, payload, payload_sha256, external_approval_ref,
			break_glass_justification, break_glass_ttl_seconds, status, requested_by, decided_by, decided_at, expires_at)
			values ($1, 'BINDING', $2, $3, 'CREATE', 'BREAK_GLASS', 'ALL', 'prod', 'dc/corp-prod', 'dc/corp-prod', 'dc/corp-prod', repeat('a', 64),
			true, '{}', repeat('b', 64), 'INC0012345', 'an incident needed this binding at once', 3600, 'APPLIED', 'livia',
			'system:break-glass', now(), now() + interval '1 day')`, bg, name, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent, zone,
			source_scope, target_scope, platform_scope, policy_sha256, distinct_approvers_required, expected_revision, payload, payload_sha256,
			reverts_cr_id, requested_by, expires_at)
			values ($1, 'BINDING', $2, $3, 'UPDATE', 'SYSTEM_REVERT', 'ANY', 'prod', 'dc/corp-prod', 'dc/corp-prod', 'dc/corp-prod', repeat('a', 64),
			false, 1, '{}', repeat('b', 64), $4, 'system:break-glass-expiry', now() + interval '1 day')`, revert, name, id, bg); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `insert into change_request_sides (change_request_id, side, scope, approval_required, basis, requested_by, cr_kind,
			decision, decided_by, decided_at) values ($1, 'TARGET', 'dc/corp-prod', true, 'BREAK_GLASS', 'livia', 'BREAK_GLASS', 'APPROVED',
			'system:break-glass', now()), ($2, 'TARGET', 'dc/corp-prod', false, 'SYSTEM_REVERT', 'system:break-glass-expiry', 'SYSTEM_REVERT',
			'APPROVED', 'system:break-glass-revert', now())`, bg, revert); err != nil {
			return err
		}
		revision := int64(1)
		_, err := audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &id, ResourceName: name, ChangeRequestID: &revert,
			Action: "APPLY_STARTED", Actor: "system:break-glass-revert", Revision: &revision})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = v.owner.Exec(context.Background(), "delete from change_requests where id in ($1, $2)", revert, bg)
	})
	if _, err := v.engine.Retry(ctx, id, "olga"); err == nil {
		t.Error("retried a PROVISIONING binding")
	}
	for _, b := range []uuid.UUID{id, plain} {
		if _, err := v.engine.Start(ctx, b); err != nil {
			t.Fatal(err)
		}
		if r := v.waitPhase(t, b, "ACTIVE"); r.phase != "ACTIVE" {
			t.Fatalf("binding %+v", r)
		}
	}
	if n := v.audited(t, id, "BREAK_GLASS_REVERTED"); n != 1 {
		t.Errorf("BREAK_GLASS_REVERTED %d", n)
	}
	if n := v.audited(t, plain, "BREAK_GLASS_REVERTED"); n != 0 {
		t.Errorf("a plain apply audited BREAK_GLASS_REVERTED %d times", n)
	}
}
