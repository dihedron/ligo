//go:build integration

package audit

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/sealing"
	"github.com/jackc/pgx/v5"
)

// signer is a local signer, as in development, from the all-zero KEK that
// every integration test uses (ligo serve's too): checkpoints they commit
// to the shared database must verify in the others.
func signer(t *testing.T) sealing.Signer {
	t.Helper()
	return sealing.NewLocalSigner(mustKEK(t, make([]byte, 32)))
}

// mustKEK is a local KEK of the given bytes.
func mustKEK(t *testing.T, key []byte) *sealing.LocalKEK {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	kek, err := sealing.NewLocalKEK(path, true)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// tampering opens a transaction as the owner, with the append-only
// triggers disabled, as only an owner or superuser could; it is rolled back.
func tampering(t *testing.T) (context.Context, pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	_, owner := setup(t)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	for _, table := range []string{"audit_log", "audit_checkpoints"} {
		if _, err := tx.Exec(ctx, "alter table "+table+" disable trigger user"); err != nil {
			t.Fatal(err)
		}
	}
	return ctx, tx
}

func appendN(t *testing.T, ctx context.Context, tx pgx.Tx, n int) []int64 {
	t.Helper()
	var ids []int64
	for i := range n {
		id, err := Append(ctx, tx, entry(i))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

// checkpoint verifies and signs the head, an hour after now or after the
// newest checkpoint, whichever is later: due whatever checkpoint other tests
// committed, some dated ahead. It returns the time it signed at.
func checkpoint(t *testing.T, ctx context.Context, tx pgx.Tx, s sealing.Signer) time.Time {
	t.Helper()
	res, err := Verify(ctx, tx, s, false)
	if err != nil || !res.Valid {
		t.Fatalf("verify before the checkpoint: %+v, %v", res, err)
	}
	var at time.Time
	if err := tx.QueryRow(ctx, "SELECT greatest(now(), coalesce(max(created_at), now())) FROM audit_checkpoints").Scan(&at); err != nil {
		t.Fatal(err)
	}
	at = at.Add(checkpointAge)
	if done, err := Checkpoint(ctx, tx, s, res, at); err != nil || !done {
		t.Fatalf("checkpoint: %v, %v", done, err)
	}
	return at
}

// rehash recomputes every hash from id on, as an attacker with the
// database but not the signing key would after changing an entry.
func rehash(t *testing.T, ctx context.Context, tx pgx.Tx, from int64) {
	t.Helper()
	var prev string
	if err := tx.QueryRow(ctx, "SELECT prev_hash FROM audit_log WHERE id = $1", from).Scan(&prev); err != nil {
		t.Fatal(err)
	}
	entries, err := load(ctx, tx, from-1, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		h, err := e.hash(prev)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "UPDATE audit_log SET prev_hash = $2, entry_hash = $3 WHERE id = $1", e.id, prev, h); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
}

// A rewrite with every hash recomputed passes the chain check, but not the
// signed checkpoint: the database alone cannot forge it (T-13).
func TestCheckpointCatchesRewrite(t *testing.T) {
	ctx, tx := tampering(t)
	s := signer(t)
	ids := appendN(t, ctx, tx, 5)
	checkpoint(t, ctx, tx, s)
	if _, err := tx.Exec(ctx, "UPDATE audit_log SET actor = 'mallory' WHERE id = $1", ids[1]); err != nil {
		t.Fatal(err)
	}
	rehash(t, ctx, tx, ids[1])
	for _, full := range []bool{false, true} {
		res, err := Verify(ctx, tx, s, full)
		if err != nil || res.Valid || res.FirstBroken != ids[4] {
			t.Errorf("full=%v: %+v, %v; want broken at the checkpoint, %d", full, res, err, ids[4])
		}
	}
}

// An entry changed without recomputing the hashes, before the newest
// checkpoint: incremental verification starts after it and misses it, the
// full pass catches it (§4.3).
func TestFullCatchesWhatIncrementalSkips(t *testing.T) {
	ctx, tx := tampering(t)
	s := signer(t)
	ids := appendN(t, ctx, tx, 5)
	checkpoint(t, ctx, tx, s)
	appendN(t, ctx, tx, 2)
	if _, err := tx.Exec(ctx, "UPDATE audit_log SET actor = 'mallory' WHERE id = $1", ids[1]); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(ctx, tx, s, false)
	if err != nil || !res.Valid || res.Entries != 2 || res.Checkpoints == 0 || res.Full {
		t.Errorf("incremental: %+v, %v; want valid over the 2 entries after the checkpoint", res, err)
	}
	res, err = Verify(ctx, tx, s, true)
	if err != nil || res.Valid || res.FirstBroken != ids[1] || !res.Full {
		t.Errorf("full: %+v, %v; want broken at %d", res, err, ids[1])
	}
}

// A checkpoint someone inserted without the key is broken, and so is a
// checkpoint whose entry was deleted.
func TestForgedAndOrphanCheckpoints(t *testing.T) {
	ctx, tx := tampering(t)
	s := signer(t)
	ids := appendN(t, ctx, tx, 3)
	checkpoint(t, ctx, tx, s)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_checkpoints (audit_id, entry_hash, created_at, key_id, signature)
		SELECT id, entry_hash, now(), $2, 'local:v1:AAAA' FROM audit_log WHERE id = $1`, ids[1], s.ID()); err != nil {
		t.Fatal(err)
	}
	if res, err := Verify(ctx, tx, s, false); err != nil || res.Valid || res.FirstBroken != ids[1] {
		t.Errorf("forged: %+v, %v; want broken at %d", res, err, ids[1])
	}
	if _, err := tx.Exec(ctx, "DELETE FROM audit_checkpoints WHERE audit_id = $1", ids[1]); err != nil {
		t.Fatal(err)
	}
	appendN(t, ctx, tx, 1)
	if _, err := tx.Exec(ctx, "DELETE FROM audit_log WHERE id = $1", ids[2]); err != nil {
		t.Fatal(err)
	}
	if res, err := Verify(ctx, tx, s, false); err != nil || res.Valid || res.FirstBroken != ids[2] {
		t.Errorf("orphan: %+v, %v; want broken at %d", res, err, ids[2])
	}
}

// Ready for pruning: entries deleted up to a checkpoint leave a chain that
// verifies from that checkpoint; deleted without one, the first remaining
// entry no longer follows genesis or any checkpoint.
func TestPrunedHead(t *testing.T) {
	ctx, tx := tampering(t)
	s := signer(t)
	if _, err := tx.Exec(ctx, "DELETE FROM audit_log; DELETE FROM audit_checkpoints"); err != nil { // rolled back
		t.Fatal(err)
	}
	ids := appendN(t, ctx, tx, 6)
	checkpoint(t, ctx, tx, s)
	if _, err := tx.Exec(ctx, "DELETE FROM audit_log WHERE id <= $1", ids[2]); err != nil {
		t.Fatal(err)
	}
	// the checkpoint at ids[5] still anchors; drop it and anchor at ids[2] instead
	if _, err := tx.Exec(ctx, "DELETE FROM audit_checkpoints"); err != nil {
		t.Fatal(err)
	}
	if res, err := Verify(ctx, tx, s, true); err != nil || res.Valid || res.FirstBroken != ids[3] {
		t.Errorf("head deleted without an anchor: %+v, %v; want broken at %d", res, err, ids[3])
	}
	var hash string
	if err := tx.QueryRow(ctx, "SELECT prev_hash FROM audit_log WHERE id = $1", ids[3]).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err := insertCheckpoint(ctx, tx, s, ids[2], hash, time.Now()); err != nil {
		t.Fatal(err)
	}
	if res, err := Verify(ctx, tx, s, true); err != nil || !res.Valid || res.Entries != 3 {
		t.Errorf("head pruned up to a checkpoint: %+v, %v; want valid over 3 entries", res, err)
	}
}

// Each batch is its own short statement: a long chain verifies under a
// statement timeout that a single pass over it would exceed.
func TestBatches(t *testing.T) {
	ctx, tx := tampering(t)
	s := signer(t)
	defer func(n int) { batchSize = n }(batchSize)
	batchSize = 500
	appendN(t, ctx, tx, 3000)
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '1s'"); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(ctx, tx, s, true)
	if err != nil || !res.Valid || res.Entries < 3000 {
		t.Errorf("%+v, %v", res, err)
	}
}

// A checkpoint is due after checkpointEntries entries or checkpointAge;
// not before.
func TestCheckpointDue(t *testing.T) {
	ctx, tx := tampering(t)
	s := signer(t)
	appendN(t, ctx, tx, 2)
	last := checkpoint(t, ctx, tx, s)
	appendN(t, ctx, tx, 2)
	res, err := Verify(ctx, tx, s, false)
	if err != nil || !res.Valid {
		t.Fatal(res, err)
	}
	if done, err := Checkpoint(ctx, tx, s, res, last); err != nil || done {
		t.Errorf("2 entries later: %v, %v; want not due", done, err)
	}
	if done, err := Checkpoint(ctx, tx, s, res, last.Add(checkpointAge)); err != nil || !done {
		t.Errorf("an hour later: %v, %v; want due", done, err)
	}
	if done, err := Checkpoint(ctx, tx, s, res, last.Add(2*checkpointAge)); err != nil || done {
		t.Errorf("at the head already: %v, %v; want nothing to sign", done, err)
	}
}

// A signer that cannot be reached is an error, never a broken chain.
func TestSignerUnavailable(t *testing.T) {
	ctx, tx := tampering(t)
	s := signer(t)
	appendN(t, ctx, tx, 2)
	checkpoint(t, ctx, tx, s)
	_, err := Verify(ctx, tx, unavailable{s}, false)
	if !errors.Is(err, sealing.ErrSignerUnavailable) {
		t.Errorf("Verify: %v, want ErrSignerUnavailable", err)
	}
}

type unavailable struct{ sealing.Signer }

func (unavailable) Verify(context.Context, string, []byte, string) error {
	return sealing.ErrSignerUnavailable
}

func (unavailable) PublicKeys(context.Context) (map[string]ed25519.PublicKey, error) {
	return nil, sealing.ErrSignerUnavailable
}
