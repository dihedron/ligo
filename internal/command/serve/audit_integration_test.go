//go:build integration

package serve

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/metrics"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
)

// TestVerifyAuditOnce: one pass under ligo_audit_verify verifies the chain,
// runs the prune step when asked (nothing is due on the shared database:
// no checkpoint there is a day old), and sets the oldest-entry gauge. The
// prune itself is tested in internal/audit.
func TestVerifyAuditOnce(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("LIGO_TEST_PG_MIGRATOR_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	pools, err := store.Open(ctx, os.Getenv("LIGO_TEST_PG_APP_DSN"), os.Getenv("LIGO_TEST_PG_READER_DSN"), store.Limits{}, os.Getenv("CI") != "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	kek := filepath.Join(t.TempDir(), "kek")
	_ = os.WriteFile(kek, make([]byte, 32), 0o600)
	local, err := sealing.NewLocalKEK(kek, true)
	if err != nil {
		t.Fatal(err)
	}
	metrics.AuditOldestEntry.Set(0)
	ran, err := verifyAuditOnce(ctx, slog.New(slog.DiscardHandler), pools.App, sealing.NewLocalSigner(local), false, true, retentions{24 * time.Hour, 24 * time.Hour})
	if err != nil || !ran {
		t.Fatalf("a pass: %v, %v", ran, err)
	}
	if metrics.Value(metrics.AuditChainValid) != 1 || metrics.Value(metrics.AuditOldestEntry) <= 0 {
		t.Errorf("chain valid %v, oldest entry %v", metrics.Value(metrics.AuditChainValid), metrics.Value(metrics.AuditOldestEntry))
	}
}
