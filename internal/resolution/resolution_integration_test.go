//go:build integration

package resolution

import (
	"context"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
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

// fixture commits a source, a target and an ACTIVE binding with an active
// snapshot, deleted at the end of the test.
func fixture(t *testing.T, owner *pgxpool.Pool, suffix, regex string) (source, binding uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	source, binding = uuid.NewV7(), uuid.NewV7()
	target := uuid.NewV7()
	err := pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by)
				values ($1, $2, 'cloud/fin-01/payments', 'cloud.internal', $3, 't', 't')`, []any{source, "s-" + suffix, regex}},
			{`insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, created_by, updated_by)
				values ($1, $2, 'oracle-prod', 'oracle.v1', 'prod', 'dc/corp-prod/ledger', 'dc/corp-prod', '{}', 't', 't')`, []any{target, "t-" + suffix}},
			{`insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{}', '[]')`, []any{target}},
			{`insert into bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
				identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, derived_principal_name,
				source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision,
				source_trust_domain, source_svid_regex, requested_spec, phase,
				active_revision, active_source_svid_regex, active_auth_config, active_spec, created_by, updated_by)
				values ($1, $2, $3, $4, 'read', 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', 'vault-prod', 'bnd_' || left(md5($1::uuid::text), 16),
				'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod', $5, 1, 1, 'cloud.internal', $6, '{}', 'ACTIVE',
				1, $6, '{"strategy":"vault"}', '{"host":"ledger-db"}', 't', 't')`,
				[]any{binding, "b-" + suffix, source, target, "ligo:apply:" + binding.String() + ":r1:a1", regex}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from bindings where id = $1", binding)
		_, _ = owner.Exec(ctx, "delete from target_access_levels where target_id = $1", target)
		_, _ = owner.Exec(ctx, "delete from targets where id = $1", target)
		_, _ = owner.Exec(ctx, "delete from sources where id = $1", source)
	})
	return source, binding
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("%s: not reached within 10s", what)
}

// TestRefresh runs the cache against the database: it loads, follows
// LISTEN/NOTIFY for a changed binding, a narrowed source (AC-61: before
// the re-apply) and a deleted binding (AC-12), reading as ligo_reader.
func TestRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := pool(t, "MIGRATOR")
	conn, err := owner.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn.Conn(), migrations.FS); err != nil {
		t.Fatal(err)
	}
	conn.Release()

	suffix := uuid.NewV7().String()[24:]
	tenant := `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/` + suffix + `-[0-9]+$`
	source, binding := fixture(t, owner, suffix, tenant)

	c := New(pool(t, "READER"), Options{FullReloadInterval: time.Hour, MaxStaleness: time.Hour, Policy: regexpolicy.DefaultPolicy()})
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	eventually(t, "initial load", func() bool { return c.Ready() })

	caller := spiffeid.RequireFromString("spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/" + suffix + "-12")
	served := func() bool {
		got, err := c.Resolve(caller, "")
		return err == nil && len(got) == 1 && got[0].ID == binding
	}
	eventually(t, "binding served", served)

	if _, err := owner.Exec(ctx, `update bindings set active_spec = '{"host":"ledger-db-2"}' where id = $1`, binding); err != nil {
		t.Fatal(err)
	}
	eventually(t, "updated snapshot", func() bool {
		got, _ := c.Resolve(caller, "")
		return len(got) == 1 && string(got[0].Spec) == `{"host": "ledger-db-2"}`
	})

	narrowed := `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/` + suffix + `-[0-9]$`
	if _, err := owner.Exec(ctx, `update sources set svid_regex = $2 where id = $1`, source, narrowed); err != nil {
		t.Fatal(err)
	}
	eventually(t, "AC-61: narrowed source no longer serves "+suffix+"-12", func() bool { return !served() })

	if _, err := owner.Exec(ctx, `update sources set svid_regex = $2 where id = $1`, source, tenant); err != nil {
		t.Fatal(err)
	}
	eventually(t, "served again", served)
	if _, err := owner.Exec(ctx, `delete from bindings where id = $1`, binding); err != nil {
		t.Fatal(err)
	}
	eventually(t, "AC-12: deleted binding no longer served", func() bool { return !served() })

	cancel()
	if err := <-done; err != nil && ctx.Err() == nil {
		t.Errorf("Run: %v", err)
	}
}
