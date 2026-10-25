//go:build integration

package invariants

import (
	"testing"
	"uuid"
)

// TestINV02 checks that the active snapshot is all set or all NULL, and
// never ahead of the requested revision.
func TestINV02(t *testing.T) {
	f := newFixture(t, "APP")
	expectCode(t, "partial active snapshot", f.exec(`update bindings set active_revision = 1 where id = $1`, f.binding), checkViolation)
	f = newFixture(t, "APP")
	expectCode(t, "active ahead of requested", f.exec(`update bindings set active_revision = 2, active_source_svid_regex = source_svid_regex,
		active_auth_config = '{}', active_spec = '{}' where id = $1`, f.binding), checkViolation)
	f = newFixture(t, "APP")
	expectOK(t, "complete active snapshot", f.exec(`update bindings set active_revision = 1, active_source_svid_regex = source_svid_regex,
		active_auth_config = '{}', active_spec = '{}' where id = $1`, f.binding))
}

// TestINV08 checks the immutable columns of sources, targets and bindings,
// and that scopes change only through re-scoping (AC-57, database part).
func TestINV08(t *testing.T) {
	for what, sql := range map[string]string{
		"source scope":          `update sources set scope = 'cloud/fin-01/hr' where id = $1`,
		"source trust domain":   `update sources set trust_domain = 'prod.internal' where id = $1`,
		"source name":           `update sources set name = 'other' where id = $1`,
		"target platform":       `update targets set platform = 'oracle-test' where id = $1`,
		"target platform scope": `update targets set platform_scope = 'dc/corp-test' where id = $1`,
		"binding wiring":        `update bindings set secret_store_instance = 'vault-test' where id = $1`,
		"binding source":        `update bindings set source_id = gen_random_uuid() where id = $1`,
		"binding scope":         `update bindings set target_scope = 'dc/corp-test' where id = $1`,
	} {
		f := newFixture(t, "APP")
		id := map[bool]uuid.UUID{true: f.source, false: f.target}[what[:6] == "source"]
		if what[:7] == "binding" {
			id = f.binding
		}
		expectCode(t, what, f.exec(sql, id), raised)
	}
	f := newFixture(t, "APP")
	f.must(t, "set local ligo.rescope = 'on'")
	expectOK(t, "scopes during re-scoping", f.exec(`update bindings set target_scope = 'dc/corp-prod/ledger2' where id = $1`, f.binding))
	expectOK(t, "source scope during re-scoping", f.exec(`update sources set scope = 'cloud/fin-01/pay' where id = $1`, f.source))
	f = newFixture(t, "APP")
	f.must(t, `update sources set state = 'RETIRED' where id = $1`, f.source)
	expectCode(t, "un-retiring a source", f.exec(`update sources set state = 'ACTIVE' where id = $1`, f.source), raised)
}

// TestINV09 checks that a workflow ID is never reused.
func TestINV09(t *testing.T) {
	f := newFixture(t, "APP")
	other := uuid.NewV7()
	f.must(t, `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by)
		values ($1, 'fin-01-payments-other', $2, 'cloud.internal', $3, 'a', 'a')`, other, f.sourceScope, f.sourceRegex)
	args := f.bindingArgs(uuid.NewV7(), "fin-01-payments-other", other, f.target, "read")
	args[8] = "ligo:apply:" + f.binding.String() + ":r1:a1"
	expectCode(t, "reused workflow ID", f.exec(f.bindingSQL(), args...), uniqueViolation)
}

// TestINV11 checks that the audit log is append-only, for the application
// (no privilege) and for its owner (trigger).
func TestINV11(t *testing.T) {
	app := newFixture(t, "APP")
	app.must(t, `insert into audit_log (action, actor, prev_hash, entry_hash) values ('SYSTEM_TEST', 'system:test', repeat('0', 64), md5(random()::text) || md5(random()::text))`)
	expectCode(t, "application update", app.exec(`update audit_log set actor = 'x'`), denied)
	app = newFixture(t, "APP")
	expectCode(t, "application delete", app.exec(`delete from audit_log`), denied)
	owner := newFixture(t, "MIGRATOR")
	owner.must(t, `insert into audit_log (action, actor, prev_hash, entry_hash) values ('SYSTEM_TEST', 'system:test', repeat('0', 64), md5(random()::text) || md5(random()::text))`)
	expectCode(t, "owner update", owner.exec(`update audit_log set actor = 'x'`), raised)
	owner = newFixture(t, "MIGRATOR")
	owner.must(t, `insert into audit_log (action, actor, prev_hash, entry_hash) values ('SYSTEM_TEST', 'system:test', repeat('0', 64), md5(random()::text) || md5(random()::text))`)
	expectCode(t, "owner delete", owner.exec(`delete from audit_log`), raised)
	owner = newFixture(t, "MIGRATOR")
	expectCode(t, "resource action without resource", owner.exec(`insert into audit_log (action, actor, prev_hash, entry_hash)
		values ('CR_CREATED', 'alice', repeat('0', 64), repeat('1', 64))`), checkViolation)
}

// TestINV14 checks that a change request is applied only when its sides
// allow it (AC-24 and AC-29, database parts).
func TestINV14(t *testing.T) {
	f := newFixture(t, "APP")
	id, err := f.insertCR(cr{})
	expectOK(t, "change request", err)
	expectCode(t, "AC-24: auto-approval of a side that needs a decision",
		f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "AUTO", required: true}), checkViolation)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{status: "APPLIED"})
	expectOK(t, "source side", f.insertSide(id, side{name: "SOURCE", scope: f.sourceScope, basis: "AUTO", decision: "APPROVED", decidedBy: "system:auto-approve"}))
	expectOK(t, "pending target side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true}))
	expectCode(t, "AC-24: applied with a pending side", f.commitCheck(), raised)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{})
	expectCode(t, "decided by the requester",
		f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true, decision: "APPROVED", decidedBy: "alice"}), checkViolation)
	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{})
	expectCode(t, "human side decided by the system",
		f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true, decision: "APPROVED", decidedBy: "system:auto-approve"}), checkViolation)
	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{})
	expectCode(t, "auto side decided by a person",
		f.insertSide(id, side{name: "SOURCE", scope: f.sourceScope, basis: "AUTO", decision: "APPROVED", decidedBy: "bob"}), checkViolation)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{approvalRef: "CHG0012345"})
	expectCode(t, "AC-29: delegated side of a person's request",
		f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "DELEGATED", required: true}), checkViolation)
	f = newFixture(t, "APP")
	awx := "spiffe://prod.internal/ns/automation-prod/sa/awx"
	id, _ = f.insertCR(cr{requestedBy: awx})
	expectOK(t, "delegated target side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "DELEGATED", required: true,
		decision: "APPROVED", decidedBy: "system:delegated-approval", requestedBy: awx}))
	expectOK(t, "source side", f.insertSide(id, side{name: "SOURCE", scope: f.sourceScope, basis: "HUMAN", required: true, requestedBy: awx}))
	expectCode(t, "delegation without approval reference", f.commitCheck(), raised)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{status: "APPLIED"})
	expectOK(t, "source side", f.insertSide(id, side{name: "SOURCE", scope: f.sourceScope, basis: "AUTO", decision: "APPROVED", decidedBy: "system:auto-approve"}))
	expectOK(t, "target side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true, decision: "APPROVED", decidedBy: "bob"}))
	expectOK(t, "applied with every side approved", f.commitCheck())
}

// TestStructure checks the sides each kind of change request must have
// (ADR-13, ADR-15).
func TestStructure(t *testing.T) {
	f := newFixture(t, "APP")
	id, _ := f.insertCR(cr{})
	expectOK(t, "target side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true}))
	expectCode(t, "cross-scope grant without a SOURCE side", f.commitCheck(), raised)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{resourceType: "SOURCE"})
	expectOK(t, "owner side", f.insertSide(id, side{name: "OWNER", scope: f.sourceScope, basis: "HUMAN", required: true}))
	expectOK(t, "second side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true}))
	expectCode(t, "source change with two sides", f.commitCheck(), raised)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{resourceType: "TARGET", ownerScope: f.platformScope})
	expectOK(t, "owner side", f.insertSide(id, side{name: "OWNER", scope: f.platformScope, basis: "HUMAN", required: true}))
	expectOK(t, "platform side", f.insertSide(id, side{name: "PLATFORM", scope: f.platformScope, basis: "HUMAN", required: true}))
	expectCode(t, "target change with a PLATFORM side in the owner's scope", f.commitCheck(), raised)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{operation: "DELETE", consent: "ANY"})
	expectOK(t, "target side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true}))
	expectOK(t, "party side", f.insertSide(id, side{name: "PARTY:security", scope: "sec/infosec", basis: "HUMAN", required: true}))
	expectCode(t, "revocation with an additional party", f.commitCheck(), raised)

	f = newFixture(t, "APP")
	_, err := f.insertCR(cr{resourceType: "SOURCE", targetScope: "dc/x"})
	expectCode(t, "source change with binding scopes", err, checkViolation)

	f = newFixture(t, "APP")
	_, err = f.insertCR(cr{})
	expectOK(t, "first pending request", err)
	_, err = f.insertCR(cr{})
	expectCode(t, "second pending request for the same resource", err, uniqueViolation)
}

// TestINV18 checks distinct people per side (AC-49, database part).
func TestINV18(t *testing.T) {
	approve := func(f *fixture, id uuid.UUID) {
		expectOK(t, "source side", f.insertSide(id, side{name: "SOURCE", scope: f.sourceScope, basis: "HUMAN", required: true, decision: "APPROVED", decidedBy: "marco"}))
		expectOK(t, "target side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true, decision: "APPROVED", decidedBy: "marco"}))
	}
	f := newFixture(t, "APP")
	id, _ := f.insertCR(cr{distinct: true})
	approve(f, id)
	expectCode(t, "AC-49: one person on two sides", f.commitCheck(), raised)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{distinct: false})
	approve(f, id)
	expectOK(t, "one person on two sides, distinct approvers waived", f.commitCheck())
}

// TestINV20 checks the rejection rules of consent ANY and ALL.
func TestINV20(t *testing.T) {
	f := newFixture(t, "APP")
	id, _ := f.insertCR(cr{operation: "DELETE", consent: "ANY", status: "REJECTED"})
	expectOK(t, "declined side", f.insertSide(id, side{name: "SOURCE", scope: f.sourceScope, basis: "HUMAN", required: true, decision: "DECLINED", decidedBy: "bob"}))
	expectOK(t, "pending side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true}))
	expectCode(t, "revocation rejected while a side may still approve", f.commitCheck(), raised)

	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{status: "REJECTED"})
	expectOK(t, "declined side", f.insertSide(id, side{name: "SOURCE", scope: f.sourceScope, basis: "HUMAN", required: true, decision: "DECLINED", decidedBy: "bob"}))
	expectOK(t, "pending side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true}))
	expectOK(t, "grant rejected by one side", f.commitCheck())
}

// TestBreakGlass checks the database rules of ADR-12 (AC-33 and AC-36,
// database parts).
func TestBreakGlass(t *testing.T) {
	bg := cr{kind: "BREAK_GLASS", requestedBy: "livia", approvalRef: "INC0012345", justification: "database outage, payments blocked", ttl: 3600}
	f := newFixture(t, "APP")
	spiffe := bg
	spiffe.requestedBy = "spiffe://prod.internal/x"
	_, err := f.insertCR(spiffe)
	expectCode(t, "AC-36: break-glass by a SPIFFE principal", err, checkViolation)
	f = newFixture(t, "APP")
	short := bg
	short.justification = "too short"
	_, err = f.insertCR(short)
	expectCode(t, "short justification", err, checkViolation)

	f = newFixture(t, "APP")
	id, err := f.insertCR(bg)
	expectOK(t, "break-glass change", err)
	expectCode(t, "AC-33: ratified by the requester", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "BREAK_GLASS", required: true,
		decision: "APPROVED", decidedBy: "system:break-glass", requestedBy: "livia", crKind: "BREAK_GLASS", ratifiedBy: "livia"}), checkViolation)
	f = newFixture(t, "APP")
	id, _ = f.insertCR(bg)
	expectOK(t, "ratified by an approver", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "BREAK_GLASS", required: true,
		decision: "APPROVED", decidedBy: "system:break-glass", requestedBy: "livia", crKind: "BREAK_GLASS", ratifiedBy: "marco"}))
	f = newFixture(t, "APP")
	id, _ = f.insertCR(bg)
	expectCode(t, "human basis on a break-glass change", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true,
		requestedBy: "livia", crKind: "BREAK_GLASS"}), checkViolation)
}

// TestImmutableDecisions checks that approval facts and decisions never
// change once recorded.
func TestImmutableDecisions(t *testing.T) {
	f := newFixture(t, "APP")
	id, _ := f.insertCR(cr{})
	expectCode(t, "policy hash", f.exec(`update change_requests set policy_sha256 = repeat('c', 64) where id = $1`, id), raised)
	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{})
	expectOK(t, "decided side", f.insertSide(id, side{name: "TARGET", scope: f.targetScope, basis: "HUMAN", required: true, decision: "APPROVED", decidedBy: "bob"}))
	expectCode(t, "changed decision", f.exec(`update change_request_sides set decision = 'DECLINED' where change_request_id = $1`, id), raised)
	f = newFixture(t, "APP")
	id, _ = f.insertCR(cr{})
	expectCode(t, "deleted side (no privilege)", f.exec(`delete from change_request_sides where change_request_id = $1`, id), denied)
}

// TestINV22 checks that no source, target or access level disappears under
// a binding (AC-67, database part).
func TestINV22(t *testing.T) {
	f := newFixture(t, "APP")
	expectCode(t, "AC-67: application deletes a source", f.exec(`delete from sources where id = $1`, f.source), denied)
	f = newFixture(t, "MIGRATOR")
	expectCode(t, "level in use removed", f.exec(`delete from target_access_levels where target_id = $1 and name = 'read'`, f.target), fkViolation)
	f = newFixture(t, "MIGRATOR")
	expectCode(t, "source of a binding removed", f.exec(`delete from sources where id = $1`, f.source), fkViolation)
	f = newFixture(t, "APP")
	other := uuid.NewV7()
	f.must(t, `insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, created_by, updated_by)
		values ($1, 'ledger-two', 'oracle-prod', 'oracle.v1', 'prod', $2, $3, '{}', 'd', 'd')`, other, f.targetScope, f.platformScope)
	expectCode(t, "binding at a level the target lacks", f.exec(f.bindingSQL(), f.bindingArgs(uuid.NewV7(), "fin-01-payments-two", f.source, other, "read")...), fkViolation)
}

// TestINV23 checks one binding per source and target (AC-68, database part).
func TestINV23(t *testing.T) {
	f := newFixture(t, "APP")
	expectCode(t, "AC-68: second binding of a pair",
		f.exec(f.bindingSQL(), f.bindingArgs(uuid.NewV7(), "fin-01-payments-ledger-2", f.source, f.target, "write")...), uniqueViolation)
}

// TestFlowColumns checks the coarse checks on stored flows (AC-64, database
// part); destinations are checked by the application (INV-24).
func TestFlowColumns(t *testing.T) {
	for what, ports := range map[string]string{"empty": "{}", "port 0": "{[0,1)}", "above 65535": "{[65535,65537)}"} {
		f := newFixture(t, "APP")
		expectCode(t, "flow ports "+what, f.exec(`insert into target_network_flows (target_id, name, protocol, destination, ports, tls)
			values ($1, 'x', 'TCP', 'h', $2::int4multirange, false)`, f.target, ports), checkViolation)
	}
	f := newFixture(t, "APP")
	expectCode(t, "server name without TLS", f.exec(`insert into target_network_flows (target_id, name, protocol, destination, ports, tls, server_name)
		values ($1, 'x', 'TCP', 'h', '{[1522,1523)}', false, 'h')`, f.target), checkViolation)
	f = newFixture(t, "APP")
	expectOK(t, "valid flow", f.exec(`insert into target_network_flows (target_id, name, protocol, destination, ports, tls, server_name)
		values ($1, 'ledger-listener', 'TCP', 'ledger-db.prod.internal', '{[1522,1523)}', true, 'ledger-db.prod.internal')`, f.target))
}

// TestNamesAndShapes checks the domains and coarse regex checks (ADR-06:
// defense in depth only).
func TestNamesAndShapes(t *testing.T) {
	for what, sql := range map[string]string{
		"invalid name":      `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by) values (gen_random_uuid(), 'Bad_Name', 'dc/x', 'td', '^spiffe://td/a/b$', 'a', 'a')`,
		"invalid scope":     `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by) values (gen_random_uuid(), 'ok', 'DC/x', 'td', '^spiffe://td/a/b$', 'a', 'a')`,
		"escaped anchor":    `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by) values (gen_random_uuid(), 'ok', 'dc/x', 'td', '^spiffe://td/a/b\$', 'a', 'a')`,
		"unanchored regex":  `insert into sources (id, name, scope, trust_domain, svid_regex, created_by, updated_by) values (gen_random_uuid(), 'ok', 'dc/x', 'td', 'spiffe://td/a/b$', 'a', 'a')`,
		"listed, no scopes": `insert into sources (id, name, scope, trust_domain, svid_regex, visibility, created_by, updated_by) values (gen_random_uuid(), 'ok', 'dc/x', 'td', '^spiffe://td/a/b$', 'LISTED', 'a', 'a')`,
	} {
		expectCode(t, what, newFixture(t, "APP").exec(sql), checkViolation)
	}
}
