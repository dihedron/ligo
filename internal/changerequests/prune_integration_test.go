//go:build integration

package changerequests

import (
	"context"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
)

// TestPrune: a closed request decided before the retention, named by no
// audit entry, goes with its sides, and SYSTEM_CR_PRUNED records it; a
// retention under 24 hours is refused (.specs/ligo-cr-pruning.md §4.3).
func TestPrune(t *testing.T) {
	s, _, owner := setup(t)
	ctx := context.Background()
	id, name := uuid.NewV7(), "old-"+uuid.NewV7().String()[24:]
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), "delete from change_requests where id = $1", id) })
	if err := pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, owner_jurisdiction,
			policy_sha256, distinct_approvers_required, payload, payload_sha256, requested_by, requested_at, expires_at, status, decided_by, decided_at)
			values ($1, 'SOURCE', $2, 'CREATE', 'STANDARD', 'ALL', 'dc/corp-prod/ledger', repeat('a', 64), true, '{}', repeat('b', 64),
			'carla', now() - interval '41 days', now() - interval '40 days', 'WITHDRAWN', 'carla', now() - interval '40 days')`, id, name); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `insert into change_request_sides (change_request_id, side, jurisdiction, approval_required, basis, requested_by, cr_kind)
			values ($1, 'OWNER', 'dc/corp-prod/ledger', true, 'HUMAN', 'carla', 'STANDARD')`, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Prune(ctx, s.DB, time.Hour, time.Now()); err == nil {
		t.Error("a retention of an hour")
	}
	n, err := Prune(ctx, s.DB, 30*24*time.Hour, time.Now())
	if err != nil || n < 1 {
		t.Fatalf("prune: %d, %v", n, err)
	}
	var left bool
	if err := owner.QueryRow(ctx, "select exists (select 1 from change_requests where id = $1)", id).Scan(&left); err != nil || left {
		t.Errorf("the old request is still there (%v)", err)
	}
	var snapshot string
	if err := owner.QueryRow(ctx, "select snapshot::text from audit_log where action = 'SYSTEM_CR_PRUNED' order by id desc limit 1").Scan(&snapshot); err != nil {
		t.Errorf("SYSTEM_CR_PRUNED: %v", err)
	}
	if n, err := Prune(ctx, s.DB, 30*24*time.Hour, time.Now()); err != nil || n != 0 {
		t.Errorf("a second prune: %d, %v", n, err)
	}
}
