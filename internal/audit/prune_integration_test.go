//go:build integration

package audit

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/sealing"
	"github.com/jackc/pgx/v5"
)

// anchorHead appends n entries and signs a checkpoint of the head, backdated
// by age; it returns the head.
func anchorHead(t *testing.T, ctx context.Context, tx pgx.Tx, n int, age time.Duration) int64 {
	t.Helper()
	appendN(t, ctx, tx, n)
	s := signer(t)
	res, err := Verify(ctx, tx, s, false)
	if err != nil || !res.Valid {
		t.Fatalf("verify: %+v, %v", res, err)
	}
	if err := insertCheckpoint(ctx, tx, s, res.head, res.headHash, time.Now().Add(-age)); err != nil {
		t.Fatal(err)
	}
	return res.head
}

func exported(t *testing.T, ctx context.Context, tx pgx.Tx, through int64) {
	t.Helper()
	if _, err := tx.Exec(ctx, "INSERT INTO audit_exports (through, sha256, actor) VALUES ($1, $2, 'test')", through, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}

// refused runs sql in a savepoint and wants an error containing want.
func refused(t *testing.T, ctx context.Context, tx pgx.Tx, want, sql string, args ...any) {
	t.Helper()
	sp, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Rollback(ctx) }()
	if _, err := sp.Exec(ctx, sql, args...); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: %v, want %q", sql, err, want)
	}
}

// TestPruneFunction: audit_prune, as ligo_app, deletes the head of the chain
// only up to a signed checkpoint that is exported and over 24 hours old; the
// chain left verifies, incrementally and in full; every other delete is
// still refused.
func TestPruneFunction(t *testing.T) {
	app, _ := setup(t)
	ctx := context.Background()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	head := anchorHead(t, ctx, tx, 5, 25*time.Hour)
	refused(t, ctx, tx, "past the newest export", "SELECT audit_prune($1)", head)
	exported(t, ctx, tx, head)
	refused(t, ctx, tx, "is not a checkpoint", "SELECT audit_prune($1)", head-1)
	refused(t, ctx, tx, "permission denied", "SELECT set_config('ligo.audit_prune', 'on', true); DELETE FROM audit_log WHERE id = "+itoa(head))
	refused(t, ctx, tx, "permission denied", "UPDATE audit_exports SET actor = 'x' WHERE through = $1", head)

	appendN(t, ctx, tx, 3)
	var deleted, oldest int64
	if err := tx.QueryRow(ctx, "SELECT audit_prune($1)", head).Scan(&deleted); err != nil || deleted < 5 {
		t.Fatalf("audit_prune: %d deleted, %v", deleted, err)
	}
	if err := tx.QueryRow(ctx, "SELECT min(id) FROM audit_log").Scan(&oldest); err != nil || oldest <= head {
		t.Errorf("oldest entry %d after pruning through %d (%v)", oldest, head, err)
	}
	for _, full := range []bool{false, true} {
		if res, err := Verify(ctx, tx, signer(t), full); err != nil || !res.Valid {
			t.Errorf("verify (full %v) after pruning: %+v, %v", full, res, err)
		}
	}
	refused(t, ctx, tx, "permission denied", "DELETE FROM audit_checkpoints WHERE audit_id = $1", head)

	// a checkpoint signed less than 24 hours ago is not prunable, exported or not
	fresh := anchorHead(t, ctx, tx, 2, time.Hour)
	exported(t, ctx, tx, fresh)
	refused(t, ctx, tx, "less than 24 hours old", "SELECT audit_prune($1)", fresh)
}

// TestPruneHoldsTheChain: an append waits for a prune in progress, then
// chains onto what is left.
func TestPruneHoldsTheChain(t *testing.T) {
	app, _ := setup(t)
	ctx := context.Background()
	tx1, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()
	head := anchorHead(t, ctx, tx1, 3, 25*time.Hour)
	exported(t, ctx, tx1, head)
	if _, err := tx1.Exec(ctx, "SELECT audit_prune($1)", head); err != nil {
		t.Fatal(err)
	}

	tx2, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx2.Rollback(ctx) }()
	done := make(chan error, 1)
	go func() { _, err := Append(ctx, tx2, entry(99)); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("an append did not wait for the prune: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	_ = tx1.Rollback(ctx)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the append still waits after the prune ended")
	}
	if res, err := Verify(ctx, tx2, signer(t), false); err != nil || !res.Valid {
		t.Errorf("verify after the append: %+v, %v", res, err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// TestTriggerException: the owner, who holds DELETE, is still refused
// without ligo.audit_prune, and on audit_checkpoints and audit_exports even
// with it.
func TestTriggerException(t *testing.T) {
	_, owner := setup(t)
	ctx := context.Background()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	appendN(t, ctx, tx, 1)
	refused(t, ctx, tx, "audit_log is append-only", "DELETE FROM audit_log")
	if _, err := tx.Exec(ctx, `INSERT INTO audit_checkpoints (audit_id, entry_hash, created_at, key_id, signature)
		VALUES (-1, $1, now(), 'k', 's')`, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	refused(t, ctx, tx, "audit_checkpoints is append-only", "SELECT set_config('ligo.audit_prune', 'on', true); DELETE FROM audit_checkpoints")
	if _, err := tx.Exec(ctx, "INSERT INTO audit_exports (through, sha256, actor) VALUES (-1, $1, 'test')", strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	refused(t, ctx, tx, "audit_exports is append-only", "SELECT set_config('ligo.audit_prune', 'on', true); DELETE FROM audit_exports")
}

// TestPrune: a prune deletes through the newest checkpoint that is signed,
// exported, signed over 24 hours ago and whose entry is older than the
// retention, audits SYSTEM_AUDIT_PRUNED, and leaves a chain that verifies;
// otherwise it does nothing. A signer that cannot be reached prunes nothing.
func TestPrune(t *testing.T) {
	app, _ := setup(t)
	ctx := context.Background()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s := signer(t)
	later := time.Now().Add(48 * time.Hour) // entries are written now: two days on, a 24h retention covers them
	oldest := func() int64 {
		t.Helper()
		var id int64
		if err := tx.QueryRow(ctx, "SELECT min(id) FROM audit_log").Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}

	first := anchorHead(t, ctx, tx, 5, 25*time.Hour)
	if p, err := Prune(ctx, tx, s, 24*time.Hour, later); err != nil || p.Deleted != 0 {
		t.Errorf("nothing exported: %+v, %v", p, err)
	}
	exported(t, ctx, tx, first)
	if p, err := Prune(ctx, tx, s, 24*time.Hour, time.Now()); err != nil || p.Deleted != 0 {
		t.Errorf("entries younger than the retention: %+v, %v", p, err)
	}
	if _, err := Prune(ctx, tx, unavailable{s}, 24*time.Hour, later); !errors.Is(err, sealing.ErrSignerUnavailable) || oldest() > first {
		t.Errorf("signer unavailable: %v, oldest %d", err, oldest())
	}
	p, err := Prune(ctx, tx, s, 24*time.Hour, later)
	if err != nil || p.Through != first || p.Export != first || p.Deleted < 5 {
		t.Fatalf("prune: %+v, %v", p, err)
	}
	if oldest() != first+1 {
		t.Errorf("oldest entry %d, want %d", oldest(), first+1)
	}
	var action, snapshot string
	if err := tx.QueryRow(ctx, "SELECT action, snapshot::text FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&action, &snapshot); err != nil ||
		action != "SYSTEM_AUDIT_PRUNED" || !strings.Contains(snapshot, `"through": `+itoa(first)) {
		t.Errorf("audited %q %s (%v)", action, snapshot, err)
	}
	for _, full := range []bool{false, true} {
		if res, err := Verify(ctx, tx, s, full); err != nil || !res.Valid {
			t.Errorf("verify (full %v) after the prune: %+v, %v", full, res, err)
		}
	}
	if p, err := Prune(ctx, tx, s, 24*time.Hour, later); err != nil || p.Deleted != 0 {
		t.Errorf("pruned again: %+v, %v", p, err)
	}

	// the newest checkpoint that qualifies wins; one signed in the last 24 hours does not
	second := anchorHead(t, ctx, tx, 3, 25*time.Hour)
	third := anchorHead(t, ctx, tx, 2, time.Hour)
	exported(t, ctx, tx, third)
	if p, err := Prune(ctx, tx, s, 24*time.Hour, later); err != nil || p.Through != second || p.Export != third {
		t.Errorf("prune through the newest qualifying checkpoint: %+v, %v, want through %d", p, err, second)
	}
}
