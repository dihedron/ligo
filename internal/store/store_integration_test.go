//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// insecure: CI's container has no TLS; the lab's DSNs use verify-full.
var insecure = os.Getenv("CI") != ""

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

// setup migrates the database and opens the pools.
func setup(t *testing.T) *Pools {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	p, err := Open(ctx, dsn(t, "APP"), dsn(t, "READER"), insecure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// owner returns a pool as ligo_migrator, for test fixtures and cleanup.
func owner(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestPools(t *testing.T) {
	ctx := context.Background()
	p := setup(t)
	for pool, want := range map[*pgxpool.Pool]string{p.App: "5s", p.Reader: "500ms"} {
		var got string
		if err := pool.QueryRow(ctx, "show statement_timeout").Scan(&got); err != nil || got != want {
			t.Errorf("statement_timeout = %q (%v), want %q", got, err, want)
		}
	}
	var user string
	if err := p.Reader.QueryRow(ctx, "select current_user").Scan(&user); err != nil || user != "ligo_reader" {
		t.Errorf("reader pool connects as %q (%v)", user, err)
	}
}

// TestMarkStep checks the fenced status update of §6.1 (ADR-08, INV-06).
func TestMarkStep(t *testing.T) {
	ctx := context.Background()
	p := setup(t)
	id, wf := insertBinding(t, owner(t))
	if err := MarkStep(ctx, p.App, id, wf, "S1", "identity ensured"); err != nil {
		t.Fatalf("current workflow: %v", err)
	}
	var step string
	if err := p.App.QueryRow(ctx, "select current_step from bindings where id = $1", id).Scan(&step); err != nil || step != "S1" {
		t.Errorf("current_step = %q (%v)", step, err)
	}
	if err := MarkStep(ctx, p.App, id, "ligo:apply:"+id.String()+":r1:a0", "S2", ""); !errors.Is(err, ErrFenced) {
		t.Errorf("superseded workflow: %v, want ErrFenced", err)
	}
	if _, err := p.App.Exec(ctx, "update bindings set phase = 'ACTIVE' where id = $1", id); err != nil {
		t.Fatal(err)
	}
	if err := MarkStep(ctx, p.App, id, wf, "S3", ""); !errors.Is(err, ErrFenced) {
		t.Errorf("binding no longer in flight: %v, want ErrFenced", err)
	}
}

// TestDecideSides covers the side decision of §4.3.
func TestDecideSides(t *testing.T) {
	ctx := context.Background()
	p := setup(t)
	cr := insertRequest(t, owner(t), "SOURCE", "TARGET")
	err := pgx.BeginFunc(ctx, p.App, func(tx pgx.Tx) error {
		_, err := DecideSides(ctx, tx, cr, "wrong", []string{"TARGET"}, "APPROVED", "bob", "")
		return err
	})
	if !errors.Is(err, ErrPayloadMismatch) {
		t.Errorf("stale hash: %v, want ErrPayloadMismatch", err)
	}
	err = pgx.BeginFunc(ctx, p.App, func(tx pgx.Tx) error {
		seq, err := DecideSides(ctx, tx, cr, payloadSHA, []string{"TARGET"}, "APPROVED", "bob", "ok")
		if err == nil && seq != 1 {
			t.Errorf("decision_seq = %d, want 1", seq)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, p.App, func(tx pgx.Tx) error {
		_, err := DecideSides(ctx, tx, cr, payloadSHA, []string{"TARGET"}, "APPROVED", "carol", "")
		return err
	})
	if !errors.Is(err, ErrSideTaken) {
		t.Errorf("side already decided: %v, want ErrSideTaken", err)
	}
	err = pgx.BeginFunc(ctx, p.App, func(tx pgx.Tx) error {
		return CloseRequest(ctx, tx, cr, "WITHDRAWN", "alice-admin", "", "")
	})
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, p.App, func(tx pgx.Tx) error {
		_, err := DecideSides(ctx, tx, cr, payloadSHA, []string{"SOURCE"}, "APPROVED", "dave", "")
		return err
	})
	if !errors.Is(err, ErrNotPending) {
		t.Errorf("withdrawn request: %v, want ErrNotPending", err)
	}
}

// TestConcurrentDecisions covers AC-21, AC-22 and AC-50 at the database:
// concurrent deciders are serialized, exactly one request decision wins,
// and two sides approved at once are both seen.
func TestConcurrentDecisions(t *testing.T) {
	ctx := context.Background()
	p := setup(t)
	o := owner(t)

	// AC-22: two request decisions at once, exactly one wins
	cr := insertRequest(t, o, "TARGET")
	errs := race(func(i int) error {
		return pgx.BeginFunc(ctx, p.App, func(tx pgx.Tx) error {
			return CloseRequest(ctx, tx, cr, []string{"WITHDRAWN", "EXPIRED"}[i], "system:test", "", "")
		})
	})
	if wins := countNil(errs); wins != 1 || !errors.Is(firstErr(errs), ErrNotPending) {
		t.Errorf("AC-22: %v, want exactly one decision and one ErrNotPending", errs)
	}

	// AC-50: two approvers of different sides at once; the second sees the
	// first, so one of them finds every side approved
	cr = insertRequest(t, o, "SOURCE", "TARGET")
	var mu sync.Mutex
	complete := 0
	errs = race(func(i int) error {
		return pgx.BeginFunc(ctx, p.App, func(tx pgx.Tx) error {
			side, actor := []string{"SOURCE", "TARGET"}[i], []string{"bob", "carol"}[i]
			if _, err := DecideSides(ctx, tx, cr, payloadSHA, []string{side}, "APPROVED", actor, ""); err != nil {
				return err
			}
			var pending int
			if err := tx.QueryRow(ctx, "select count(*) from change_request_sides where change_request_id = $1 and decision is null", cr).Scan(&pending); err != nil {
				return err
			}
			if pending == 0 {
				mu.Lock()
				complete++
				mu.Unlock()
			}
			return nil
		})
	})
	if countNil(errs) != 2 || complete != 1 {
		t.Errorf("AC-50: errors %v, %d transactions saw the request complete, want 1", errs, complete)
	}
}

// race runs f(0) and f(1) at the same time.
func race(f func(int) error) []error {
	errs := make([]error, 2)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := range 2 {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			errs[i] = f(i)
		}()
	}
	start.Done()
	done.Wait()
	return errs
}

func countNil(errs []error) int {
	n := 0
	for _, err := range errs {
		if err == nil {
			n++
		}
	}
	return n
}

func firstErr(errs []error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

const payloadSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// insertRequest commits a pending binding change request with HUMAN sides
// (SOURCE, TARGET or both), deleted at the end of the test.
func insertRequest(t *testing.T, o *pgxpool.Pool, sides ...string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewV7()
	name := "test-" + id.String()[24:]
	scopes := map[string]string{"SOURCE": "cloud/fin-01/payments", "TARGET": "dc/corp-prod/ledger"}
	err := pgx.BeginFunc(ctx, o, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, zone,
			source_scope, target_scope, platform_scope, policy_sha256, distinct_approvers_required, expected_revision, payload,
			payload_sha256, requested_by, expires_at)
			values ($1, 'BINDING', $2, 'DELETE', 'STANDARD', 'ANY', 'prod', 'cloud/fin-01/payments', 'dc/corp-prod/ledger',
			'dc/corp-prod', repeat('a', 64), true, 1, '{}', $3, 'alice', now() + interval '1 day')`, id, name, payloadSHA); err != nil {
			return err
		}
		for _, s := range sides {
			if _, err := tx.Exec(ctx, `insert into change_request_sides (change_request_id, side, scope, approval_required, basis, requested_by, cr_kind)
				values ($1, $2, $3, true, 'HUMAN', 'alice', 'STANDARD')`, id, s, scopes[s]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = o.Exec(context.Background(), "delete from change_requests where id = $1", id) })
	return id
}

// insertBinding commits a source, a target, its level and a PROVISIONING
// binding, deleted at the end of the test; it returns the binding's id and
// workflow ID.
func insertBinding(t *testing.T, o *pgxpool.Pool) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	source, target, binding := uuid.NewV7(), uuid.NewV7(), uuid.NewV7()
	suffix := binding.String()[24:]
	wf := "ligo:apply:" + binding.String() + ":r1:a1"
	regex := `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/x$`
	err := pgx.BeginFunc(ctx, o, func(tx pgx.Tx) error {
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
				identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
				source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision,
				source_trust_domain, source_svid_regex, requested_spec, created_by, updated_by)
				values ($1, $2, $3, $4, 'read', 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', 'vault-prod', 'vault-static', 'bnd_' || left(md5($1::uuid::text), 16),
				'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod', $5, 1, 1, 'cloud.internal', $6, '{}', 't', 't')`,
				[]any{binding, "b-" + suffix, source, target, wf, regex}},
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
		_, _ = o.Exec(ctx, "delete from bindings where id = $1", binding)
		_, _ = o.Exec(ctx, "delete from target_access_levels where target_id = $1", target)
		_, _ = o.Exec(ctx, "delete from targets where id = $1", target)
		_, _ = o.Exec(ctx, "delete from sources where id = $1", source)
	})
	return binding, wf
}
