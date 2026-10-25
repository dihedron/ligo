//go:build integration

package migrate

import (
	"context"
	"errors"
	"os"
	"testing"
	"testing/fstest"

	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// connect opens a connection with the DSN in the environment variable env
// (test/lab/lab.sh env, or the CI job); a missing variable fails the test.
func connect(t *testing.T, env string) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv(env)
	if dsn == "" {
		t.Fatalf("%s is not set: run the integration tests with test/lab/lab.sh test", env)
	}
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// TestApply migrates the database and checks that a second run does
// nothing.
func TestApply(t *testing.T) {
	ctx := context.Background()
	conn := connect(t, "LIGO_TEST_PG_MIGRATOR_DSN")
	if _, err := Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	again, err := Apply(ctx, conn, migrations.FS)
	if err != nil || len(again) != 0 {
		t.Errorf("second Apply = (%v, %v), want nothing applied", again, err)
	}
	var n int
	if err := conn.QueryRow(ctx, "select count(*) from schema_migrations where version = '001'").Scan(&n); err != nil || n != 1 {
		t.Errorf("001 recorded %d times (%v)", n, err)
	}
}

// TestSchema checks the objects of §4.2.
func TestSchema(t *testing.T) {
	ctx := context.Background()
	conn := connect(t, "LIGO_TEST_PG_MIGRATOR_DSN")
	if _, err := Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	for kind, query := range map[string]string{
		"table":   "select count(*) from pg_tables where schemaname = 'public' and tablename = $1",
		"view":    "select count(*) from pg_views where schemaname = 'public' and viewname = $1",
		"trigger": "select count(*) from pg_trigger where tgname = $1",
		"type":    "select count(*) from pg_type where typname = $1",
	} {
		for _, name := range map[string][]string{
			"table": {"sources", "targets", "target_access_levels", "target_network_flows", "bindings", "binding_stage_state",
				"binding_propagation_queue", "change_requests", "change_request_sides", "admin_sessions", "audit_log",
				"system_settings", "notification_outbox"},
			"view":    {"v_active_bindings", "v_active_binding_flows"},
			"trigger": {"trg_sources_immutable", "trg_targets_immutable", "trg_bindings_immutable", "trg_change_requests_check", "trg_change_request_sides_check", "trg_audit_no_update"},
			"type":    {"binding_phase", "approval_basis", "change_request_status", "scope_path", "resource_name"},
		}[kind] {
			var n int
			if err := conn.QueryRow(ctx, query, name).Scan(&n); err != nil || n != 1 {
				t.Errorf("%s %s: found %d (%v)", kind, name, n, err)
			}
		}
	}
}

// TestPrivileges checks the database roles of §4.1: the reader sees only
// the views, and the application never deletes a source (AC-67).
func TestPrivileges(t *testing.T) {
	ctx := context.Background()
	if _, err := Apply(ctx, connect(t, "LIGO_TEST_PG_MIGRATOR_DSN"), migrations.FS); err != nil {
		t.Fatal(err)
	}
	reader := connect(t, "LIGO_TEST_PG_READER_DSN")
	if _, err := reader.Exec(ctx, "select * from v_active_bindings limit 1"); err != nil {
		t.Errorf("reader on v_active_bindings: %v", err)
	}
	for _, table := range []string{"sources", "bindings", "audit_log"} {
		checkDenied(t, reader, "select * from "+table+" limit 1")
	}
	app := connect(t, "LIGO_TEST_PG_APP_DSN")
	if _, err := app.Exec(ctx, "select * from sources limit 1"); err != nil {
		t.Errorf("app on sources: %v", err)
	}
	checkDenied(t, app, "delete from sources")
	checkDenied(t, app, "delete from change_request_sides")
	checkDenied(t, app, "update audit_log set id = id")
	checkDenied(t, connect(t, "LIGO_TEST_PG_DBOS_DSN"), "select * from public.sources limit 1") // no USAGE on the schema
}

// TestTampered refuses a migration whose content changed after it was
// applied.
func TestTampered(t *testing.T) {
	ctx := context.Background()
	conn := connect(t, "LIGO_TEST_PG_MIGRATOR_DSN")
	if _, err := Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	_, err := Apply(ctx, conn, fstest.MapFS{"001_init_schema.sql": {Data: []byte("select 1;")}})
	if !errors.Is(err, ErrChanged) {
		t.Errorf("edited migration: %v, want ErrChanged", err)
	}
}

// checkDenied expects a permission error (SQLSTATE 42501).
func checkDenied(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	_, err := conn.Exec(context.Background(), sql)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("%q: got %v, want permission denied", sql, err)
	}
}
