//go:build integration

package workflows

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
)

func (v *env) reconciler() *Reconciler {
	return &Reconciler{Engine: v.engine, MaxConcurrent: 100, Rotation: map[string]time.Duration{"pg": 24 * time.Hour}}
}

func (v *env) workflowID(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var wf string
	if err := v.owner.QueryRow(context.Background(), "select workflow_id from bindings where id = $1", id).Scan(&wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

// TestReconcile: an ACTIVE binding is re-applied at the same revision as a
// new attempt, rotating its static secret only once rotation_interval has
// passed; the next pass leaves the re-applied binding alone while busy
// (§6.6, §6.4 rotation flag).
func TestReconcile(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	ctx := context.Background()
	due, recent := v.active(t, ""), v.active(t, "")
	if _, err := v.owner.Exec(ctx, "update bindings set last_rotated_at = now() - interval '48 hours' where id = $1", due); err != nil {
		t.Fatal(err)
	}
	v.fake.rotations = nil
	if _, err := v.reconciler().Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{due, recent} {
		if r := v.waitPhase(t, id, "ACTIVE"); r.phase != "ACTIVE" {
			t.Fatalf("binding %+v", r)
		}
		if wf := v.workflowID(t, id); !strings.HasPrefix(wf, "ligo:reapply:") || !strings.HasSuffix(wf, ":r1:a2") {
			t.Errorf("workflow %s", wf)
		}
		if v.audited(t, id, "REAPPLY_STARTED") != 1 {
			t.Errorf("REAPPLY_STARTED missing for %s", id)
		}
	}
	rotations := map[bool]int{}
	for _, r := range v.fake.rotations {
		rotations[r]++
	}
	if rotations[true] != 1 || rotations[false] != 1 {
		t.Errorf("rotations %v: one due, one not", v.fake.rotations)
	}
}

// TestAC66: a binding on a deprecated target and level is still served and
// reconciled.
func TestAC66(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	ctx := context.Background()
	id := v.active(t, "")
	if _, err := v.owner.Exec(ctx, "update target_access_levels set state = 'DEPRECATED' where target_id = (select target_id from bindings where id = $1)", id); err != nil {
		t.Fatal(err)
	}
	if _, err := v.owner.Exec(ctx, "update targets set state = 'DEPRECATED' where id = (select target_id from bindings where id = $1)", id); err != nil {
		t.Fatal(err)
	}
	if _, err := v.reconciler().Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if r := v.waitPhase(t, id, "ACTIVE"); r.phase != "ACTIVE" {
		t.Fatalf("binding %+v", r)
	}
	if v.audited(t, id, "REAPPLY_STARTED") != 1 {
		t.Error("REAPPLY_STARTED missing")
	}
	var served int
	if err := v.owner.QueryRow(ctx, "select count(*) from v_active_bindings where id = $1", id).Scan(&served); err != nil || served != 1 {
		t.Errorf("served %d (%v)", served, err)
	}
}

// TestAC78: a re-apply refused by the target because a bound tightened fails
// the binding, which keeps its last active snapshot.
func TestAC78(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	ctx := context.Background()
	id := v.active(t, "")
	before := v.row(t, id)
	v.fake.targetFail = pluginsdk.Error(codes.FailedPrecondition, "PRIVILEGE_OUT_OF_BOUNDS", "LEDGER_RW_ROLE is not in grantable_roles", false)
	if _, err := v.reconciler().Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	r := v.waitPhase(t, id, "FAILED")
	if r.phase != "FAILED" || r.step != "ensureTarget" || !strings.Contains(r.message, "PRIVILEGE_OUT_OF_BOUNDS") {
		t.Fatalf("binding %+v", r)
	}
	if r.activeRevision == nil || *r.activeRevision != 1 || r.spec != before.spec || r.auth != before.auth {
		t.Errorf("snapshot %+v, was %+v", r, before)
	}
	var served int
	if err := v.owner.QueryRow(ctx, "select count(*) from v_active_bindings where id = $1", id).Scan(&served); err != nil || served != 1 {
		t.Errorf("served %d (%v)", served, err)
	}
}

// TestReconcileNoRotation: a platform without rotation_interval has no
// scheduled rotation, however old the static secret (§6.4 rotation flag).
func TestReconcileNoRotation(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	ctx := context.Background()
	id := v.active(t, "")
	if _, err := v.owner.Exec(ctx, "update bindings set last_rotated_at = now() - interval '48 hours' where id = $1", id); err != nil {
		t.Fatal(err)
	}
	v.fake.rotations = nil
	r := v.reconciler()
	r.Rotation = nil
	if _, err := r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if b := v.waitPhase(t, id, "ACTIVE"); b.phase != "ACTIVE" {
		t.Fatalf("binding %+v", b)
	}
	if slices.Contains(v.fake.rotations, true) {
		t.Errorf("rotations %v: none scheduled", v.fake.rotations)
	}
}

// TestReconcileLimits: busy bindings are skipped, at most max_concurrent
// re-applies run at once, and maintenance mode starts nothing (§6.6).
func TestReconcileLimits(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	ctx := context.Background()
	busy := v.binding(t) // PROVISIONING, never started
	a, b := v.active(t, ""), v.active(t, "")
	if _, err := v.owner.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	r := v.reconciler()
	n, err := r.Reconcile(ctx)
	_, _ = v.owner.Exec(ctx, "update system_settings set maintenance_mode = false")
	if err != nil || n != 0 {
		t.Errorf("during maintenance: %d started (%v)", n, err)
	}
	v.fake.storeBlock = make(chan struct{}) // the first re-apply stays running
	r.MaxConcurrent = 1
	if n, err := r.Reconcile(ctx); err != nil || n != 1 {
		t.Fatalf("first pass: %d started (%v)", n, err)
	}
	if n, err := r.Reconcile(ctx); err != nil || n != 0 {
		t.Errorf("at max_concurrent: %d started (%v)", n, err)
	}
	reapplied := 0
	for _, id := range []uuid.UUID{a, b} {
		if strings.HasPrefix(v.workflowID(t, id), "ligo:reapply:") {
			reapplied++
		}
	}
	if reapplied != 1 || v.row(t, busy).phase != "PROVISIONING" || v.workflowID(t, busy) != "ligo:apply:"+busy.String()+":r1:a1" {
		t.Errorf("%d re-applied; busy %s", reapplied, v.workflowID(t, busy))
	}
}

// TestRetention: finished workflows older than workflow_retention are
// purged from DBOS (§6.7, EXT-06).
func TestRetention(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	id := v.active(t, "")
	wf := v.workflowID(t, id)
	ran, err := (&Sweeper{Engine: v.engine, Retention: time.Nanosecond}).Sweep(context.Background())
	if err != nil || !ran {
		t.Fatalf("sweep: %t %v", ran, err)
	}
	if _, err := dbos.RetrieveWorkflow[string](v.engine.DBOS, wf); !errors.Is(err, dbos.ErrNonExistentWorkflow) {
		t.Errorf("the finished workflow is still there: %v", err)
	}
}

// TestReconcileSingleton: while another replica holds the reconciler's
// lock, a pass starts nothing (§6.6).
func TestReconcileSingleton(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	ctx := context.Background()
	conn, err := v.engine.DB.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('ligo_reconciler'))"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtext('ligo_reconciler'))") }()
	if n, err := v.reconciler().Reconcile(ctx); err != nil || n != 0 {
		t.Errorf("under another replica's lock: %d started, %v", n, err)
	}
}

// TestRotate: an operator's rotation re-applies an ACTIVE binding with
// rotation forced; another phase is invalid, maintenance refuses it.
func TestRotate(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	ctx := context.Background()
	id := v.active(t, "")
	v.fake.rotations = nil
	if _, err := v.owner.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	_, err := v.engine.Rotate(ctx, id, "olga")
	_, _ = v.owner.Exec(ctx, "update system_settings set maintenance_mode = false")
	if e := (*changerequests.Error)(nil); !errors.As(err, &e) || e.Slug != "maintenance" {
		t.Errorf("in maintenance: %v", err)
	}
	if _, err := v.engine.Rotate(ctx, id, "olga"); err != nil {
		t.Fatal(err)
	}
	if r := v.waitPhase(t, id, "ACTIVE"); r.phase != "ACTIVE" || !strings.HasSuffix(v.workflowID(t, id), ":r1:a2") {
		t.Fatalf("binding %+v", r)
	}
	if len(v.fake.rotations) != 1 || !v.fake.rotations[0] {
		t.Errorf("rotations %v", v.fake.rotations)
	}
	if _, err := v.owner.Exec(ctx, "update bindings set phase = 'FAILED' where id = $1", id); err != nil {
		t.Fatal(err)
	}
	if _, err := v.engine.Rotate(ctx, id, "olga"); err == nil {
		t.Error("rotated a FAILED binding")
	}
}
