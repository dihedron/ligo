//go:build integration

package sources

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/store"
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

func caller(name, role string, scopes ...string) changerequests.Caller {
	return changerequests.Caller{Principal: authz.Principal{Name: name}, Grants: authz.Grants{{Role: role, Scopes: scopes}}}
}

var (
	alice = caller("alice", config.RoleOperator, "cloud/*")
	bob   = caller("bob", config.RoleApprover, "cloud/fin-01/*")
	eve   = caller("eve", config.RoleOperator, "dc/*")
)

func setup(t *testing.T) (*Service, *pgxpool.Pool) {
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
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), insecure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	cfg := example(t)
	s := &Service{DB: pools.App, Rules: rules(t)}
	s.Requests = &changerequests.Service{DB: pools.App, Policy: cfg.Policy(), TTL: cfg.Authorization.Approval.ChangeRequestTTL,
		Resources: map[string]changerequests.Resource{"SOURCE": s}}
	return s, owner
}

// body is a request body for src, with the extra fields of an update.
func body(t *testing.T, src Source, extra map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	for k, v := range extra {
		m[k] = v
	}
	data, _ = json.Marshal(m)
	return data
}

// registered files and approves a new source, removed with its requests at
// the end of the test.
func registered(t *testing.T, s *Service, owner *pgxpool.Pool) Source {
	t.Helper()
	ctx := context.Background()
	src := source()
	src.Metadata.Name += "-" + uuid.NewV7().String()[24:]
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from binding_propagation_queue where binding_id in (select b.id from bindings b join sources s on s.id = b.source_id where s.name = $1)", src.Metadata.Name)
		_, _ = owner.Exec(ctx, "delete from change_requests where resource_type = 'SOURCE' and resource_name = $1", src.Metadata.Name)
		_, _ = owner.Exec(ctx, "delete from sources where name = $1", src.Metadata.Name)
	})
	r, err := s.Create(ctx, alice, body(t, src, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	return src
}

func row(t *testing.T, owner *pgxpool.Pool, name string) (id uuid.UUID, state, regex string, revision int64) {
	t.Helper()
	err := owner.QueryRow(context.Background(), "select id, state, svid_regex, revision from sources where name = $1 and state <> 'RETIRED'", name).
		Scan(&id, &state, &regex, &revision)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// TestAC60: a sample the regex does not match is refused; a valid source
// waits for the approver of its scope, then is ACTIVE.
func TestAC60(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	bad := source()
	bad.Identity.SampleSPIFFEIDs = append(bad.Identity.SampleSPIFFEIDs, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/other")
	if _, err := s.Create(ctx, alice, body(t, bad, nil)); slug(err) != "sample-not-matched" {
		t.Fatalf("bad sample: %v", err)
	}
	src := source()
	src.Metadata.Name += "-" + uuid.NewV7().String()[24:]
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), "delete from change_requests where resource_type = 'SOURCE' and resource_name = $1", src.Metadata.Name)
		_, _ = owner.Exec(context.Background(), "delete from sources where name = $1", src.Metadata.Name)
	})
	if _, err := s.Create(ctx, eve, body(t, src, nil)); slug(err) != "forbidden" {
		t.Errorf("operator of another scope: %v", err)
	}
	r, err := s.Create(ctx, alice, body(t, src, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || len(r.Sides) != 1 || r.Sides[0].Name != "OWNER" || r.Sides[0].Scope != "cloud/fin-01/payments" || r.Sides[0].Basis != changerequests.BasisHuman {
		t.Fatalf("request %+v", r)
	}
	if _, err := s.Create(ctx, alice, body(t, src, nil)); slug(err) != "change-request-pending" {
		t.Errorf("second request: %v", err)
	}
	if _, err := s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	id, state, _, revision := row(t, owner, src.Metadata.Name)
	var resource uuid.UUID
	if err := owner.QueryRow(ctx, "select resource_id from change_requests where id = $1", r.ID).Scan(&resource); err != nil || resource != id {
		t.Errorf("resource_id %v (%v), want %v", resource, err, id)
	}
	if state != "ACTIVE" || revision != 1 {
		t.Errorf("state %s revision %d", state, revision)
	}
	if _, err := s.Create(ctx, alice, body(t, src, nil)); slug(err) != "invalid-transition" { // §8.4: a create of an existing name
		t.Errorf("name in use: %v", err)
	}
}

// TestNarrowingPropagates: an approved narrowing is applied with a new
// revision and queues the source's bindings at priority 0 (§6.2.1).
func TestNarrowingPropagates(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	src := registered(t, s, owner)
	id, _, _, _ := row(t, owner, src.Metadata.Name)
	binding := insertBinding(t, owner, id)
	narrow := src
	narrow.Identity.SVIDRegex = `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/ledger-1$`
	narrow.Identity.SampleSPIFFEIDs = []string{sample1}
	if _, err := s.Update(ctx, alice, src.Metadata.Name, body(t, narrow, map[string]any{"expectedRevision": 2})); slug(err) != "revision-conflict" {
		t.Errorf("stale revision: %v", err)
	}
	r, err := s.Update(ctx, alice, src.Metadata.Name, body(t, narrow, map[string]any{"expectedRevision": 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	_, _, regex, revision := row(t, owner, src.Metadata.Name)
	if regex != narrow.Identity.SVIDRegex || revision != 2 {
		t.Errorf("regex %s revision %d", regex, revision)
	}
	var priority int
	var cause string
	if err := owner.QueryRow(ctx, "select priority, cause from binding_propagation_queue where binding_id = $1 and cause_change_request_id = $2", binding, r.ID).
		Scan(&priority, &cause); err != nil || priority != 0 || cause != "SOURCE" {
		t.Errorf("propagation: priority %d cause %s (%v)", priority, cause, err)
	}
	rows, _ := owner.Query(ctx, "select action from audit_log where change_request_id = $1 order by id", r.ID)
	actions, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	if len(actions) < 2 || actions[len(actions)-2] != "SOURCE_UPDATED" || actions[len(actions)-1] != "PROPAGATION_ENQUEUED" {
		t.Errorf("audit %v", actions)
	}
	var changed string
	if err := owner.QueryRow(ctx, "select snapshot->>'changed' from audit_log where change_request_id = $1 and action = 'SOURCE_UPDATED'", r.ID).
		Scan(&changed); err != nil || changed != `["identity"]` {
		t.Errorf("SOURCE_UPDATED changed %s (%v)", changed, err)
	}
	if _, err := s.SetState(ctx, alice, src.Metadata.Name, "retire", 2, "", nil); slug(err) != "resource-in-use" {
		t.Errorf("retire with a binding: %v", err)
	}
}

// TestStates: deprecate, reactivate and retire are updates of the state,
// each allowed only from its states (§7.2.3 step 9).
func TestStates(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	src := registered(t, s, owner)
	if _, err := s.SetState(ctx, eve, src.Metadata.Name, "deprecate", 1, "", nil); slug(err) != "not-found" {
		t.Errorf("caller without a role on the scope: %v", err)
	}
	if _, err := s.SetState(ctx, alice, src.Metadata.Name, "reactivate", 1, "", nil); slug(err) != "invalid-transition" {
		t.Errorf("reactivate ACTIVE: %v", err)
	}
	revision := int64(1)
	for _, op := range []string{"deprecate", "reactivate", "retire"} {
		r, err := s.SetState(ctx, alice, src.Metadata.Name, op, revision, "", nil)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if _, err := s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		revision++
	}
	var state string
	if err := owner.QueryRow(ctx, "select state from sources where name = $1", src.Metadata.Name).Scan(&state); err != nil || state != "RETIRED" {
		t.Errorf("state %s (%v)", state, err)
	}
	if _, err := s.SetState(ctx, alice, src.Metadata.Name, "reactivate", revision, "", nil); slug(err) != "not-found" {
		t.Errorf("a retired source is final: %v", err)
	}
}

// insertBinding commits a target, its level and a binding of source,
// deleted at the end of the test.
func insertBinding(t *testing.T, o *pgxpool.Pool, source uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	target, binding := uuid.NewV7(), uuid.NewV7()
	suffix := binding.String()[24:]
	err := pgx.BeginFunc(ctx, o, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, created_by, updated_by)
				values ($1, $2, 'oracle-prod', 'oracle.v1', 'prod', 'dc/corp-prod/ledger', 'dc/corp-prod', '{}', 't', 't')`, []any{target, "t-" + suffix}},
			{`insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{}', '[]')`, []any{target}},
			{`insert into bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
				identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
				source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision,
				source_trust_domain, source_svid_regex, requested_spec, created_by, updated_by)
				values ($1, $2, $3, $4, 'read', 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', 'vault-prod', 'vault-static', 'bnd_' || left(md5($1::uuid::text), 16),
				'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod', $5, 1, 1, 'cloud.internal', $6, '{}', 't', 't')`,
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
		_, _ = o.Exec(ctx, "delete from bindings where id = $1", binding)
		_, _ = o.Exec(ctx, "delete from target_access_levels where target_id = $1", target)
		_, _ = o.Exec(ctx, "delete from targets where id = $1", target)
	})
	return binding
}
