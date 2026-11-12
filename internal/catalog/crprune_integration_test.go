//go:build integration

package catalog

import (
	"context"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
)

// TestChangeRequestsPrune: change_requests_prune deletes a closed request,
// with its sides, once it was decided before older_than, no audit entry
// names it, no binding holds it as its open break-glass change, and no
// request that stays depends on it or reverts it; a chain goes whole.
// ligo_app may run it and may not delete a request any other way
// (.specs/ligo-cr-pruning.md §4.3, §4.4). Here in catalog for its
// helpers: the rules are the schema's.
func TestChangeRequestsPrune(t *testing.T) {
	r, o, x := setup(t)
	ctx := context.Background()
	src := source(t, o, "fin-01-payments-q-"+x, "cloud/fin-01/payments", "cloud.internal", `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/q`+x+`$`)
	tgt := target(t, o, "ledger-q-"+x, "dc/corp-prod/ledger", "PRIVATE", "[]")
	tx, err := o.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	old := time.Now().Add(-40 * 24 * time.Hour)

	n := 0
	// request files a closed request decided at decided, of a source, or of
	// a binding when dependsOn or reverts is set; it returns its id
	request := func(status string, decided time.Time, dependsOn, reverts *uuid.UUID) uuid.UUID {
		t.Helper()
		n++
		id := uuid.NewV7()
		decidedBy := any("carla")
		decidedAt := any(decided)
		if status == "PENDING" {
			decidedBy, decidedAt = nil, nil
		}
		var err error
		if dependsOn == nil && reverts == nil {
			_, err = tx.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, owner_jurisdiction,
				policy_sha256, distinct_approvers_required, payload, payload_sha256, requested_by, requested_at, expires_at, status, decided_by, decided_at)
				values ($1, 'SOURCE', $2, 'CREATE', 'STANDARD', 'ALL', 'cloud/fin-01/payments', repeat('a', 64), true, '{}', repeat('b', 64),
				'carla', $3::timestamptz, $3::timestamptz + interval '1 day', $4::change_request_status, $5, $6)`,
				id, "fin-01-payments-q"+string(rune('a'+n))+"-"+x, decided.Add(-time.Hour), status, decidedBy, decidedAt)
		} else {
			kind, op, consent := "STANDARD", "CREATE", "ALL"
			if reverts != nil {
				kind, op, consent = "SYSTEM_REVERT", "UPDATE", "ANY"
			}
			_, err = tx.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, realm,
				source_jurisdiction, target_jurisdiction, platform_jurisdiction, policy_sha256, distinct_approvers_required, payload, payload_sha256,
				requested_by, requested_at, expires_at, status, decided_by, decided_at, depends_on_cr_id, reverts_cr_id, expected_revision)
				values ($1, 'BINDING', $2, $3::change_request_op, $4::change_request_kind, $11::consent_rule, 'prod', 'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod',
				repeat('a', 64), true, '{}', repeat('b', 64), 'carla', $5::timestamptz, $5::timestamptz + interval '1 day', $6::change_request_status, $7, $8, $9, $10,
				CASE WHEN $3::change_request_op = 'CREATE' THEN NULL ELSE 1 END)`,
				id, "fin-01-payments-q"+string(rune('a'+n))+"-"+x, op, kind, decided.Add(-time.Hour), status, decidedBy, decidedAt, dependsOn, reverts, consent)
		}
		if err != nil {
			t.Fatal(err)
		}
		// the sides change_request_check wants: a source's OWNER; a binding's
		// TARGET, and SOURCE as the jurisdictions differ; a revert's TARGET
		sides := map[string]string{"OWNER": "cloud/fin-01/payments"}
		switch {
		case reverts != nil:
			sides = map[string]string{"TARGET": "dc/corp-prod/ledger"}
		case dependsOn != nil:
			sides = map[string]string{"TARGET": "dc/corp-prod/ledger", "SOURCE": "cloud/fin-01/payments"}
		}
		for side, j := range sides {
			if _, err := tx.Exec(ctx, `insert into change_request_sides (change_request_id, side, jurisdiction, approval_required, basis, requested_by, cr_kind)
				select $1, $2, $3, kind <> 'SYSTEM_REVERT', CASE WHEN kind = 'SYSTEM_REVERT' THEN 'SYSTEM_REVERT' ELSE 'HUMAN' END::approval_basis,
					'carla', kind from change_requests where id = $1`, id, side, j); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	exists := func(id uuid.UUID) bool {
		t.Helper()
		var ok bool
		if err := tx.QueryRow(ctx, "select exists (select 1 from change_requests where id = $1)", id).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	gone := request("WITHDRAWN", old, nil, nil)
	recent := request("WITHDRAWN", time.Now(), nil, nil)
	pending := request("PENDING", old, nil, nil)
	audited := request("WITHDRAWN", old, nil, nil)
	if _, err := audit.Append(ctx, tx, audit.Entry{ResourceType: "SOURCE", ResourceName: "q", ChangeRequestID: &audited, Action: "CR_WITHDRAWN", Actor: "carla"}); err != nil {
		t.Fatal(err)
	}
	held := request("WITHDRAWN", old, nil, nil) // a source request standing in for a binding's open break-glass change
	b := uuid.NewV7()
	if _, err := tx.Exec(ctx, `insert into bindings (id, name, source_id, target_id, access_level, realm, platform_type, platform,
		identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
		source_jurisdiction, target_jurisdiction, platform_jurisdiction, workflow_id, source_revision, target_revision,
		source_trust_domain, source_svid_regex, requested_spec, created_by, updated_by, break_glass_cr_id, break_glass_expires_at)
		values ($1, $2, $3, $4, 'read', 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', 'vault-prod', 'vault-static',
		'bnd_' || left(md5($1::uuid::text), 16), 'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod', 'w', 1, 1, 'cloud.internal',
		'^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/x$', '{}', 't', 't', $5, now() + interval '1 hour')`, b, "fin-01-payments-qb-"+x, src, tgt, held); err != nil {
		t.Fatal(err)
	}
	// a chain kept whole: the dependant is audited, so what it depends on stays
	base := request("WITHDRAWN", old, nil, nil)
	dependant := request("WITHDRAWN", old, &base, nil)
	if _, err := audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceName: "q", ChangeRequestID: &dependant, Action: "CR_WITHDRAWN", Actor: "carla"}); err != nil {
		t.Fatal(err)
	}
	// a chain that goes whole: neither is held
	base2 := request("WITHDRAWN", old, nil, nil)
	revert := request("WITHDRAWN", old, nil, &base2)

	refused := func(want, sql string, args ...any) {
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
	// committed, then judged as ligo_app in a transaction rolled back
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = o.Exec(context.Background(), "delete from bindings where id = $1", b) }) // before setup's own cleanup
	if tx, err = r.DB.Begin(ctx); err != nil {
		t.Fatal(err)
	}
	refused("24 hours", "select change_requests_prune(now() - interval '1 hour')")
	refused("permission denied", "delete from change_requests where id = $1", gone)
	var deleted int64
	if err := tx.QueryRow(ctx, "select change_requests_prune(now() - interval '30 days')").Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		id   uuid.UUID
		kept bool
	}{
		{"closed long ago", gone, false},
		{"decided recently", recent, true},
		{"pending", pending, true},
		{"named by an audit entry", audited, true},
		{"a binding's open break-glass change", held, true},
		{"depended on by a request that stays", base, true},
		{"the dependant", dependant, true},
		{"a chain's base", base2, false},
		{"its revert", revert, false},
	} {
		if exists(c.id) != c.kept {
			t.Errorf("%s: kept %v, want %v", c.name, !c.kept, c.kept)
		}
	}
	var sides int
	if err := tx.QueryRow(ctx, "select count(*) from change_request_sides where change_request_id = any($1)", []uuid.UUID{gone, base2, revert}).Scan(&sides); err != nil || sides != 0 {
		t.Errorf("%d sides of pruned requests left (%v)", sides, err)
	}
	if deleted < 3 {
		t.Errorf("deleted %d, want at least 3", deleted)
	}
}
