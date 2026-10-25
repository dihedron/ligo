//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"

	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func pool(t *testing.T, role string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if dsn == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func setup(t *testing.T) (app, owner *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	owner = pool(t, "MIGRATOR")
	conn, err := owner.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := migrate.Apply(ctx, conn.Conn(), migrations.FS); err != nil {
		t.Fatal(err)
	}
	return pool(t, "APP"), owner
}

func entry(n int) Entry {
	return Entry{Action: "SYSTEM_TEST", Actor: "system:test", Snapshot: json.RawMessage(`{"n":` + string(rune('0'+n%10)) + `}`)}
}

// TestChain appends entries concurrently as ligo_app and verifies the chain
// (§4.3, INV-11).
func TestChain(t *testing.T) {
	ctx := context.Background()
	app, _ := setup(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- pgx.BeginFunc(ctx, app, func(tx pgx.Tx) error {
				_, err := Append(ctx, tx, entry(i))
				return err
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	res, err := Verify(ctx, app)
	if err != nil || !res.Valid || res.Entries < 8 {
		t.Errorf("Verify = %+v, %v", res, err)
	}
}

// TestAC18 modifies an entry directly, as only a database owner or
// superuser could (disabling the append-only trigger), and expects Verify
// to report it; the transaction is rolled back.
func TestAC18(t *testing.T) {
	ctx := context.Background()
	_, owner := setup(t)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var ids []int64
	for i := range 3 {
		id, err := Append(ctx, tx, entry(i))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if res, err := Verify(ctx, tx); err != nil || !res.Valid {
		t.Fatalf("before tampering: %+v, %v", res, err)
	}
	if _, err := tx.Exec(ctx, "alter table audit_log disable trigger trg_audit_no_update"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "update audit_log set actor = 'mallory' where id = $1", ids[1]); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(ctx, tx)
	if err != nil || res.Valid || res.FirstBroken != ids[1] {
		t.Errorf("after tampering with %d: %+v, %v", ids[1], res, err)
	}
}
