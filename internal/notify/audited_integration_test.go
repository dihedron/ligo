//go:build integration

package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAudited: audit entries announce their events through the hook, in
// their transaction: one CR_AWAITING_APPROVAL per pending side, to that
// side's scope; BINDING_REVOKED to the scopes other than the deciding
// side's, only for consent ANY; PROPAGATION_FAILED only for a propagated
// revision; deprecations to the scopes of the affected bindings; system
// events to every subscriber; entries that are no event write nothing.
func TestAudited(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
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
	x := uuid.NewV7().String()[24:]
	events := []string{"CR_AWAITING_APPROVAL", "BINDING_REVOKED", "PROPAGATION_FAILED", "SOURCE_DEPRECATED", "CR_INTERCONNECT_DENIED",
		"SYSTEM_MAINTENANCE_ENABLED", "BINDING_EXPIRING"}
	hooks := map[string]string{"all-" + x: "", "dc-" + x: "dc/corp-prod/*", "cloud-" + x: "cloud/*"}
	var webhooks []config.Webhook
	for name, scope := range hooks {
		w := config.Webhook{Name: name, Events: events}
		if scope != "" {
			w.Scopes = []string{scope}
		}
		webhooks = append(webhooks, w)
	}
	audit.Hook = (&Outbox{Webhooks: webhooks}).Audited
	t.Cleanup(func() { audit.Hook = nil })

	src, tgt, bnd := uuid.NewV7(), uuid.NewV7(), uuid.NewV7()
	create, revoke := uuid.NewV7(), uuid.NewV7()
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from notification_outbox where webhook like $1", "%-"+x)
		_, _ = owner.Exec(ctx, "delete from change_requests where id in ($1, $2)", create, revoke)
		_, _ = owner.Exec(ctx, "delete from bindings where id = $1", bnd)
		_, _ = owner.Exec(ctx, "delete from target_access_levels where target_id = $1", tgt)
		_, _ = owner.Exec(ctx, "delete from targets where id = $1", tgt)
		_, _ = owner.Exec(ctx, "delete from sources where id = $1", src)
	})
	err = pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by) values ($1, $2, 'cloud/fin-01/payments',
				'cloud.internal', $3, 't', 't')`, []any{src, "src-" + x, `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/` + x + `$`}},
			{`insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, created_by, updated_by)
				values ($1, $2, 'oracle-prod', 'oracle.v1', 'prod', 'dc/corp-prod/ledger', 'dc/corp-prod', '{}', 't', 't')`, []any{tgt, "tgt-" + x}},
			{`insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{}', '[]')`, []any{tgt}},
			{`insert into bindings (id, name, source_id, target_id, access_level, zone, platform_type, platform,
				identity_provider_type, identity_provider_instance, secret_store_type, secret_store_instance, secret_storage_strategy, derived_principal_name,
				source_scope, target_scope, platform_scope, workflow_id, source_revision, target_revision, source_trust_domain, source_svid_regex,
				requested_spec, created_by, updated_by)
				values ($1, $2, $3, $4, 'read', 'prod', 'oracle.v1', 'oracle-prod', 'openldap.v1', 'ldap-prod', 'vault.v1', 'vault-prod', 'vault-static',
				'bnd_' || left(md5($1::uuid::text), 16), 'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod', 'w', 1, 1, 'cloud.internal', $5,
				'{}', 't', 't')`, []any{bnd, "b-" + x, src, tgt, `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/` + x + `$`}},
			{`insert into change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent, zone, source_scope, target_scope,
				platform_scope, policy_sha256, distinct_approvers_required, payload, payload_sha256, requested_by, expires_at)
				values ($1, 'BINDING', $2, NULL, 'CREATE', 'STANDARD', 'ALL', 'prod', 'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod',
				repeat('a', 64), false, '{}', repeat('b', 64), 'carla', now() + interval '1 day')`, []any{create, "new-" + x}},
			{`insert into change_request_sides (change_request_id, side, scope, approval_required, basis, requested_by, cr_kind, decision, decided_by, decided_at)
				values ($1, 'SOURCE', 'cloud/fin-01/payments', false, 'AUTO', 'carla', 'STANDARD', 'APPROVED', 'system:auto-approve', now()),
				($1, 'TARGET', 'dc/corp-prod/ledger', true, 'HUMAN', 'carla', 'STANDARD', NULL, NULL, NULL),
				($1, 'PARTY:security', 'sec/infosec', true, 'HUMAN', 'carla', 'STANDARD', NULL, NULL, NULL)`, []any{create}},
			{`insert into change_requests (id, resource_type, resource_name, resource_id, operation, kind, consent, zone, source_scope, target_scope,
				platform_scope, policy_sha256, distinct_approvers_required, payload, payload_sha256, requested_by, expires_at, expected_revision)
				values ($1, 'BINDING', $2, $3, 'DELETE', 'STANDARD', 'ANY', 'prod', 'cloud/fin-01/payments', 'dc/corp-prod/ledger', 'dc/corp-prod',
				repeat('a', 64), false, '{}', repeat('c', 64), 'dino', now() + interval '1 day', 1)`, []any{revoke, "b-" + x, bnd}},
			{`insert into change_request_sides (change_request_id, side, scope, approval_required, basis, requested_by, cr_kind, decision, decided_by, decided_at)
				values ($1, 'PLATFORM', 'dc/corp-prod', true, 'HUMAN', 'dino', 'STANDARD', 'APPROVED', 'dora', now())`, []any{revoke}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return fmt.Errorf("%s: %w", strings.Fields(q.sql)[2], err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	two := int64(2)
	snap := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	for _, tc := range []struct {
		name    string
		entry   audit.Entry
		event   string
		perHook map[string]int // rows of event per webhook prefix, after this case
	}{
		{"pending sides", audit.Entry{ResourceType: "BINDING", ResourceName: "new-" + x, ChangeRequestID: &create, Action: "CR_CREATED", Actor: "carla"},
			"CR_AWAITING_APPROVAL", map[string]int{"all": 2, "dc": 1, "cloud": 0}},
		{"granting change applied", audit.Entry{ResourceType: "BINDING", ResourceName: "new-" + x, ChangeRequestID: &create, Action: "CR_APPROVED", Actor: "dora"},
			"BINDING_REVOKED", map[string]int{"all": 0, "dc": 0, "cloud": 0}},
		{"revocation applied", audit.Entry{ResourceType: "BINDING", ResourceID: &bnd, ResourceName: "b-" + x, ChangeRequestID: &revoke, Action: "CR_APPROVED", Actor: "dora"},
			"BINDING_REVOKED", map[string]int{"all": 1, "dc": 1, "cloud": 1}},
		{"failure of an apply", audit.Entry{ResourceType: "BINDING", ResourceID: &bnd, ResourceName: "b-" + x, Action: "PROVISION_FAILURE", Actor: "system:workflow", Revision: &two},
			"PROPAGATION_FAILED", map[string]int{"all": 0, "dc": 0, "cloud": 0}},
		{"propagation started", audit.Entry{ResourceType: "BINDING", ResourceID: &bnd, ResourceName: "b-" + x, Action: "PROPAGATION_STARTED", Actor: "system:propagator", Revision: &two},
			"PROPAGATION_FAILED", map[string]int{"all": 0, "dc": 0, "cloud": 0}},
		{"failure of a propagation", audit.Entry{ResourceType: "BINDING", ResourceID: &bnd, ResourceName: "b-" + x, Action: "PROVISION_FAILURE", Actor: "system:workflow", Revision: &two},
			"PROPAGATION_FAILED", map[string]int{"all": 1, "dc": 1, "cloud": 1}},
		{"source deprecated", audit.Entry{ResourceType: "SOURCE", ResourceID: &src, ResourceName: "src-" + x, Action: "SOURCE_DEPRECATED", Actor: "carla"},
			"SOURCE_DEPRECATED", map[string]int{"all": 1, "dc": 1, "cloud": 1}},
		{"interconnection denied", audit.Entry{ResourceType: "BINDING", ResourceName: "denied-" + x, Action: "CR_INTERCONNECT_DENIED", Actor: "tina",
			Snapshot: snap(map[string]string{"sourceScope": "dc/corp-test", "targetScope": "dc/corp-prod/ledger"})},
			"CR_INTERCONNECT_DENIED", map[string]int{"all": 1, "dc": 1, "cloud": 0}},
		{"maintenance", audit.Entry{Action: "SYSTEM_MAINTENANCE_ENABLED", Actor: "root", Snapshot: snap(map[string]string{"reason": "upgrade-" + x})},
			"SYSTEM_MAINTENANCE_ENABLED", map[string]int{"all": 1, "dc": 1, "cloud": 1}},
		{"expiry warning", audit.Entry{ResourceType: "BINDING", ResourceID: &bnd, ResourceName: "b-" + x, Action: "BINDING_EXPIRY_WARNED", Actor: "system:expiry"},
			"BINDING_EXPIRING", map[string]int{"all": 1, "dc": 1, "cloud": 1}},
		{"no event", audit.Entry{Action: "CONFIG_LOADED", Actor: "system:startup"}, "CONFIG_LOADED", map[string]int{"all": 0, "dc": 0, "cloud": 0}},
	} {
		if err := pgx.BeginFunc(ctx, pools.App, func(tx pgx.Tx) error { _, err := audit.Append(ctx, tx, tc.entry); return err }); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for prefix, want := range tc.perHook { // rows so far: the cases of one event add up in order
			var n int
			if err := owner.QueryRow(ctx, "select count(*) from notification_outbox where webhook = $1 and event = $2", prefix+"-"+x, tc.event).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != want {
				t.Errorf("%s: webhook %s has %d %s rows, want %d", tc.name, prefix, n, tc.event, want)
			}
		}
	}

	var side, sideScope string
	var payload map[string]any
	var raw []byte
	if err := owner.QueryRow(ctx, "select payload from notification_outbox where webhook = $1 and event = 'CR_AWAITING_APPROVAL'", "dc-"+x).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &payload)
	side, sideScope = fmt.Sprint(payload["side"]), fmt.Sprint(payload["sideScope"])
	if side != "TARGET" || sideScope != "dc/corp-prod/ledger" || payload["changeRequestId"] != create.String() || payload["sourceScope"] != "cloud/fin-01/payments" {
		t.Errorf("awaiting payload: %v", payload)
	}
	if err := owner.QueryRow(ctx, "select payload from notification_outbox where webhook = $1 and event = 'BINDING_EXPIRING'", "all-"+x).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &payload)
	if r, _ := payload["resource"].(map[string]any); r["source"] != "src-"+x || r["target"] != "tgt-"+x || r["platform"] != "oracle-prod" || payload["zone"] != "prod" {
		t.Errorf("binding payload: %v", payload)
	}
}
