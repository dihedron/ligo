//go:build integration

package workflows

import (
	"context"
	"slices"
	"strings"
	"testing"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
)

// deleting moves a binding to DELETING as an applied delete does (§6.2.2):
// a new attempt and workflow, the active snapshot cleared at once.
func (v *env) deleting(t *testing.T, id uuid.UUID) {
	t.Helper()
	_, err := v.owner.Exec(context.Background(), `update bindings set phase = 'DELETING', operation = 'DELETE', attempt = attempt + 1,
		workflow_id = format('ligo:delete:%s:r%s:a%s', id, revision, attempt + 1), current_step = 'INIT', active_revision = null,
		active_source_svid_regex = null, active_auth_config = null, active_spec = null where id = $1`, id)
	if err != nil {
		t.Fatal(err)
	}
}

func (v *env) exists(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	var n int
	if err := v.owner.QueryRow(context.Background(), "select count(*) from bindings where id = $1", id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func (v *env) audited(t *testing.T, id uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := v.owner.QueryRow(context.Background(), "select count(*) from audit_log where resource_id = $1 and action = $2", id, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// active applies a binding to ACTIVE.
func (v *env) active(t *testing.T, name string) uuid.UUID {
	t.Helper()
	id := v.bindingNamed(t, name)
	h, err := v.engine.Start(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := wait(t, h); out != "ACTIVE" {
		t.Fatalf("apply: %q, %v", out, err)
	}
	return id
}

// TestDelete: the stages are cleaned in reverse order, each after the later
// ones' rows are gone (INV-04); the binding is gone, its workloads lost it
// when the delete committed (AC-12), and a foreign resource is skipped.
func TestDelete(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	v.fake.skipped = map[string]bool{"TARGET": true}
	id := v.active(t, "")
	var served int
	view := func() int {
		_ = v.owner.QueryRow(context.Background(), "select count(*) from v_active_bindings where id = $1", id).Scan(&served)
		return served
	}
	if view() != 1 {
		t.Fatal("the active binding is not served")
	}
	v.deleting(t, id)
	if view() != 0 {
		t.Error("AC-12: a deleting binding is served")
	}
	h, err := v.engine.Start(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := wait(t, h); out != "DELETED" || err != nil {
		t.Fatalf("delete: %q, %v", out, err)
	}
	if !slices.Equal(v.fake.cleanups, []string{"SECRET_STORE", "TARGET", "IDENTITY"}) || len(v.fake.laterPresent) > 0 {
		t.Errorf("cleanups %v; INV-04 %v", v.fake.cleanups, v.fake.laterPresent)
	}
	if v.exists(t, id) || v.audited(t, id, "DELETE_COMPLETED") != 1 || v.audited(t, id, "CLEANUP_SKIPPED_NOT_OWNER") != 1 {
		t.Errorf("binding left, or audit missing")
	}
}

// TestAC10: Stage 2 fails after Stage 1 created its principal; the delete
// cleans the target, with no artifact, then the identity; nothing was
// stored, so the store is not called.
func TestAC10(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	v.fake.targetFail = pluginsdk.Error(codes.FailedPrecondition, "SCHEMA_GONE", "the schema does not exist", false)
	id := v.binding(t)
	h, err := v.engine.Start(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := wait(t, h); out != "FAILED" {
		t.Fatalf("apply: %q", out)
	}
	v.deleting(t, id)
	if h, err = v.engine.Start(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if out, err := wait(t, h); out != "DELETED" || err != nil {
		t.Fatalf("delete: %q, %v", out, err)
	}
	if !slices.Equal(v.fake.cleanups, []string{"TARGET", "IDENTITY"}) || v.exists(t, id) {
		t.Errorf("cleanups %v", v.fake.cleanups)
	}
}

// TestDeleteRetry: a failed cleanup leaves the binding DELETE_FAILED; a
// retry is a new attempt that resumes where it stopped (§6.5).
func TestDeleteRetry(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	v.fake.cleanupFail = map[string]int{"TARGET": 1}
	id := v.active(t, "")
	v.deleting(t, id)
	h, err := v.engine.Start(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := wait(t, h); out != "DELETE_FAILED" {
		t.Fatalf("delete: %q", out)
	}
	if r := v.row(t, id); r.phase != "DELETE_FAILED" || !strings.HasPrefix(r.message, "CLEANUP_DENIED") || v.audited(t, id, "DELETE_FAILURE") != 1 {
		t.Fatalf("binding %+v", r)
	}
	if h, err = v.engine.Retry(context.Background(), id, "alice"); err != nil {
		t.Fatal(err)
	}
	if out, err := wait(t, h); out != "DELETED" || err != nil {
		t.Fatalf("retry: %q, %v", out, err)
	}
	if !slices.Equal(v.fake.cleanups, []string{"SECRET_STORE", "TARGET", "IDENTITY"}) || v.exists(t, id) {
		t.Errorf("cleanups %v", v.fake.cleanups)
	}
}

// TestAC11: a binding deleted and created again with the same name has a
// new ID and new workflow IDs, and provisions (INV-09).
func TestAC11(t *testing.T) {
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_SVID)
	name := "again-" + uuid.NewV7().String()[24:]
	first := v.active(t, name)
	v.deleting(t, first)
	h, err := v.engine.Start(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := wait(t, h); out != "DELETED" {
		t.Fatalf("delete: %q", out)
	}
	second := v.active(t, name)
	if second == first {
		t.Error("the same ID")
	}
}
