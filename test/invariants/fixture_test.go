//go:build integration

// Package invariants holds one test suite per system invariant (§3.12,
// §11.1 rule 3). The suites here check what the database enforces on its
// own (§4.2), whatever the application does; they run against the lab
// (test/lab/lab.sh test ./test/invariants) and in CI.
package invariants

import (
	"context"
	"errors"
	"os"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SQLSTATE codes the database answers with.
const (
	checkViolation  = "23514"
	uniqueViolation = "23505"
	fkViolation     = "23503"
	raised          = "P0001" // RAISE EXCEPTION in a trigger
	denied          = "42501"
)

var conns = map[string]*pgx.Conn{}

// open is the transaction of the latest fixture of each role: a connection
// holds one transaction at a time.
var open = map[string]pgx.Tx{}

func TestMain(m *testing.M) {
	ctx := context.Background()
	for _, role := range []string{"MIGRATOR", "APP"} {
		dsn := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
		if dsn == "" {
			println("LIGO_TEST_PG_" + role + "_DSN is not set: run the integration tests with test/lab/lab.sh test")
			os.Exit(1)
		}
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			println(err.Error())
			os.Exit(1)
		}
		conns[role] = conn
	}
	if _, err := migrate.Apply(ctx, conns["MIGRATOR"], migrations.FS); err != nil {
		println(err.Error())
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// fixture is one source, one target with levels read and write, and a
// binding between them at read, created in a transaction that is never
// committed.
type fixture struct {
	tx             pgx.Tx
	source, target uuid.UUID
	binding        uuid.UUID
	sourceScope    string
	targetScope    string
	platformScope  string
	sourceRegex    string
}

// newFixture begins a transaction as role ("APP" or "MIGRATOR"), creates
// the base rows and rolls everything back at the end of the test.
func newFixture(t *testing.T, role string) *fixture {
	t.Helper()
	ctx := context.Background()
	if prev := open[role]; prev != nil {
		_ = prev.Rollback(ctx)
	}
	tx, err := conns[role].Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	open[role] = tx
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	f := &fixture{
		tx: tx, source: uuid.NewV7(), target: uuid.NewV7(), binding: uuid.NewV7(),
		sourceScope: "cloud/fin-01/payments", targetScope: "dc/corp-prod/ledger", platformScope: "dc/corp-prod",
		sourceRegex: `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/ledger-[0-9]+$`,
	}
	f.must(t, `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by)
		values ($1, 'fin-01-payments-ledger', $2, 'cloud.internal', $3, 'alice', 'alice')`, f.source, f.sourceScope, f.sourceRegex)
	f.must(t, `insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, created_by, updated_by)
		values ($1, 'ledger-schema', 'oracle-prod', 'oracle.v1', 'prod', $2, $3, '{}', 'dora', 'dora')`, f.target, f.targetScope, f.platformScope)
	for _, level := range []string{"read", "write"} {
		f.must(t, `insert into target_access_levels (target_id, name, grants, privileges) values ($1, $2, '{}', '[]')`, f.target, level)
	}
	f.insertBinding(t, f.binding, "fin-01-payments-ledger", f.source, f.target, "read")
	return f
}

// insertBinding adds a binding; it must succeed.
func (f *fixture) insertBinding(t *testing.T, id uuid.UUID, name string, source, target uuid.UUID, level string) {
	t.Helper()
	f.must(t, f.bindingSQL(), f.bindingArgs(id, name, source, target, level)...)
}

func (f *fixture) bindingSQL() string {
	return `insert into bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
		identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
		source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision,
		source_trust_domain, source_svid_regex, requested_spec, created_by, updated_by)
		values ($1, $2, $3, $4, $5, 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', 'vault-prod', 'vault-static', 'bnd_' || left(md5($1::uuid::text), 16),
		$6, $7, $8, $9, 1, 1, 'cloud.internal', $10, '{}', 'alice', 'alice')`
}

func (f *fixture) bindingArgs(id uuid.UUID, name string, source, target uuid.UUID, level string) []any {
	return []any{id, name, source, target, level, f.sourceScope, f.targetScope, f.platformScope,
		"ligo:apply:" + id.String() + ":r1:a1", f.sourceRegex}
}

// cr describes a change request; zero fields get the defaults of a
// standard binding CREATE across scopes.
type cr struct {
	resourceType, operation, kind, consent string
	status, requestedBy, approvalRef       string
	ownerScope, targetScope                string // overrides
	distinct                               bool
	justification                          string
	ttl                                    int
}

// insertCR adds a change request and returns its id; the error, if any, is
// returned for the caller to check.
func (f *fixture) insertCR(c cr) (uuid.UUID, error) {
	id := uuid.NewV7()
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&c.resourceType, "BINDING")
	def(&c.operation, "CREATE")
	def(&c.kind, "STANDARD")
	def(&c.consent, "ALL")
	def(&c.status, "PENDING")
	def(&c.requestedBy, "alice")
	var owner, source, target, platform, zone any
	switch c.resourceType {
	case "SOURCE":
		owner = f.sourceScope
	case "TARGET":
		owner, platform, zone = f.targetScope, f.platformScope, "prod"
	default:
		source, target, platform, zone = f.sourceScope, f.targetScope, f.platformScope, "prod"
	}
	if c.ownerScope != "" {
		owner = c.ownerScope
	}
	if c.targetScope != "" {
		target = c.targetScope
	}
	var ref, justification, ttl, decidedBy any
	if c.approvalRef != "" {
		ref = c.approvalRef
	}
	if c.justification != "" {
		justification, ttl = c.justification, c.ttl
	}
	if c.status == "APPLIED" || c.status == "REJECTED" {
		decidedBy = "system:test"
	}
	var expected any
	if c.operation != "CREATE" {
		expected = 1
	}
	_, err := f.tx.Exec(context.Background(), `insert into change_requests (id, resource_type, resource_name, operation, kind, consent,
		zone, owner_scope, source_scope, target_scope, platform_scope, policy_sha256, distinct_approvers_required,
		expected_revision, payload, payload_sha256, status, external_approval_ref, break_glass_justification,
		break_glass_ttl_seconds, requested_by, decided_by, decided_at, expires_at)
		values ($1, $2, 'fin-01-payments-ledger', $3, $4, $5, $6, $7, $8, $9, $10, repeat('a', 64), $11, $12, '{}', repeat('b', 64), $13,
		$14, $15, $16, $17, $18::varchar, case when $18::varchar is null then null else now() end, now() + interval '3 days')`,
		id, c.resourceType, c.operation, c.kind, c.consent, zone, owner, source, target, platform, c.distinct,
		expected, c.status, ref, justification, ttl, c.requestedBy, decidedBy)
	return id, err
}

// side describes a side of a change request.
type side struct {
	name, scope, basis  string
	required            bool
	decision, decidedBy string
	ratifiedBy          string
	requestedBy, crKind string
}

func (f *fixture) insertSide(id uuid.UUID, s side) error {
	if s.requestedBy == "" {
		s.requestedBy = "alice"
	}
	if s.crKind == "" {
		s.crKind = "STANDARD"
	}
	var decision, decidedBy, ratifiedBy any
	if s.decision != "" {
		decision, decidedBy = s.decision, s.decidedBy
	}
	if s.ratifiedBy != "" {
		ratifiedBy = s.ratifiedBy
	}
	_, err := f.tx.Exec(context.Background(), `insert into change_request_sides (change_request_id, side, scope, approval_required, basis,
		requested_by, cr_kind, decision, decided_by, decided_at, ratified_by, ratified_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9::varchar, case when $9::varchar is null then null else now() end,
		$10::varchar, case when $10::varchar is null then null else now() end)`,
		id, s.name, s.scope, s.required, s.basis, s.requestedBy, s.crKind, decision, decidedBy, ratifiedBy)
	return err
}

// commitCheck runs the deferred constraint triggers now, as a commit would.
func (f *fixture) commitCheck() error {
	_, err := f.tx.Exec(context.Background(), "set constraints all immediate")
	return err
}

// exec runs a statement and returns its error.
func (f *fixture) exec(sql string, args ...any) error {
	_, err := f.tx.Exec(context.Background(), sql, args...)
	return err
}

// must runs a statement that has to succeed.
func (f *fixture) must(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.exec(sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// expectCode checks that err carries SQLSTATE code.
func expectCode(t *testing.T, what string, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Errorf("%s: got %v, want SQLSTATE %s", what, err, code)
		return
	}
	if os.Getenv("LIGO_TEST_SHOW_REFUSALS") != "" {
		t.Logf("%s: %s %s", what, pgErr.ConstraintName, pgErr.Message)
	}
}

// expectOK checks that err is nil.
func expectOK(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: %v", what, err)
	}
}
