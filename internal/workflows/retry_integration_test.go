//go:build integration

package workflows

import (
	"context"
	"testing"
	"time"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
)

// nextRetry is the binding's next_retry_at, or nil.
func (v *env) nextRetry(t *testing.T, id uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := v.owner.QueryRow(context.Background(), "select next_retry_at from bindings where id = $1", id).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// due makes the binding's automatic retry due now.
func (v *env) due(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := v.owner.Exec(context.Background(), "update bindings set next_retry_at = now() - interval '1 second' where id = $1", id); err != nil {
		t.Fatal(err)
	}
}

// autoRetries counts the attempts the sweeper started for the binding.
func (v *env) autoRetries(t *testing.T, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := v.owner.QueryRow(context.Background(), "select count(*) from audit_log where resource_id = $1 and actor = 'system:auto-retry'", id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAutoRetry: a delete that failed on a retryable error, as in an outage of
// the store, gets a next retry; the sweeper leaves it until it is due and
// while maintenance mode is on, then retries it as system:auto-retry, and the
// delete completes (§6.3).
func TestAutoRetry(t *testing.T) {
	ctx := context.Background()
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	v.fake.cleanupFail, v.fake.retryable = map[string]int{"TARGET": 2}, true // both in-step attempts
	id := v.active(t, "")
	v.deleting(t, id)
	h, err := v.engine.Start(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := wait(t, h); out != "DELETE_FAILED" {
		t.Fatalf("delete: %q", out)
	}
	at := v.nextRetry(t, id)
	if at == nil || !at.After(time.Now()) {
		t.Fatalf("next retry %v, want one in the future", at)
	}
	v.sweep(t)
	if r := v.row(t, id); r.phase != "DELETE_FAILED" || v.autoRetries(t, id) != 0 {
		t.Fatalf("retried before it was due: %+v", r)
	}
	v.due(t, id)
	if _, err := v.owner.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	v.sweep(t)
	_, _ = v.owner.Exec(ctx, "update system_settings set maintenance_mode = false")
	if r := v.row(t, id); r.phase != "DELETE_FAILED" || v.autoRetries(t, id) != 0 {
		t.Fatalf("retried in maintenance mode: %+v", r)
	}
	v.sweep(t)
	deadline := time.Now().Add(30 * time.Second)
	for v.exists(t, id) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if v.exists(t, id) || v.autoRetries(t, id) != 1 {
		t.Fatalf("not deleted by an automatic retry: exists %t, retries %d", v.exists(t, id), v.autoRetries(t, id))
	}
}

// TestAutoRetryNotRetryable: a failure its plugin calls final waits for an
// operator, as before: no next retry, and the sweeper leaves it.
func TestAutoRetryNotRetryable(t *testing.T) {
	ctx := context.Background()
	v := setup(t, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	v.fake.cleanupFail = map[string]int{"TARGET": 1}
	id := v.active(t, "")
	v.deleting(t, id)
	h, err := v.engine.Start(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := wait(t, h); out != "DELETE_FAILED" {
		t.Fatalf("delete: %q", out)
	}
	if at := v.nextRetry(t, id); at != nil {
		t.Fatalf("next retry %v for a final failure", at)
	}
	v.sweep(t)
	if r := v.row(t, id); r.phase != "DELETE_FAILED" || v.autoRetries(t, id) != 0 {
		t.Fatalf("a final failure was retried: %+v", r)
	}
}
