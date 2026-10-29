//go:build integration

package workflows

import (
	"context"
	"testing"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
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
