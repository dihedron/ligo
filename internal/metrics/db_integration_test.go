//go:build integration

package metrics

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

// TestDB: every database gauge is collected from the migrated schema, a
// source added shows in ligo_sources, and a failed query is a scrape
// failure, not a broken scrape.
func TestDB(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = migrate.Apply(ctx, conn, migrations.FS)
	_ = conn.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), os.Getenv("CI") != "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)

	reg := prometheus.NewRegistry()
	reg.MustRegister(&DB{Pool: pools.App, Logger: slog.New(slog.DiscardHandler), Rotation: map[string]time.Duration{"oracle-prod": time.Hour},
		Timeout: 5 * time.Second})
	value := func(family string, labels map[string]string) float64 {
		t.Helper()
		got, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range got {
			if f.GetName() != family {
				continue
			}
		next:
			for _, m := range f.GetMetric() {
				for _, l := range m.GetLabel() {
					if labels[l.GetName()] != l.GetValue() {
						continue next
					}
				}
				return m.GetGauge().GetValue()
			}
		}
		return -1
	}
	if v := value("ligo_db_scrape_success", nil); v != 1 {
		t.Fatalf("ligo_db_scrape_success %v", v)
	}
	for _, f := range []string{"ligo_propagation_queue_depth", "ligo_propagation_oldest_seconds"} {
		for _, p := range []string{"0", "1"} {
			if v := value(f, map[string]string{"priority": p}); v < 0 {
				t.Errorf("%s{priority=%s} missing", f, p)
			}
		}
	}
	for _, w := range []string{"24h", "7d"} {
		if v := value("ligo_bindings_expiring", map[string]string{"within": w}); v < 0 {
			t.Errorf("ligo_bindings_expiring{within=%s} missing", w)
		}
	}
	before := max(value("ligo_sources", map[string]string{"state": "ACTIVE"}), 0)
	name := "metrics-" + uuid.NewV7().String()[24:]
	if _, err := owner.Exec(ctx, `insert into sources (id, name, scope, trust_domain, svid_regex, visibility, created_by, updated_by)
		values ($1, $2, 'dc/corp-prod', 'prod.internal', '^spiffe://prod\.internal/m$', 'PUBLIC', 't', 't')`, uuid.NewV7(), name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), "delete from sources where name = $1", name) })
	if v := value("ligo_sources", map[string]string{"state": "ACTIVE"}); v != before+1 {
		t.Errorf("ligo_sources{state=ACTIVE} %v, want %v", v, before+1)
	}

	// a closed pool: every query fails, the scrape still answers
	broken, err := pgxpool.New(ctx, dsn(t, "APP"))
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	reg = prometheus.NewRegistry()
	reg.MustRegister(&DB{Pool: broken, Logger: slog.New(slog.DiscardHandler), Timeout: time.Second})
	if v := value("ligo_db_scrape_success", nil); v != 0 {
		t.Errorf("ligo_db_scrape_success %v with a closed pool", v)
	}
}
