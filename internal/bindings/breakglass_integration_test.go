//go:build integration

package bindings

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

var livia = caller("livia", role(config.RoleBreakGlass, "dc/corp-prod/*"))

const justification = "payments outage, the ledger read path is needed now"

// ledgerSource adds a source in dc/corp-prod/ledger, the scope of the
// ledger target: a same-scope binding has one side.
func ledgerSource(t *testing.T, o *pgxpool.Pool, w *world, n string) string {
	t.Helper()
	name := "ledger-src-" + n + "-" + w.suffix
	if _, err := o.Exec(context.Background(), `insert into sources (id, name, scope, trust_domain, svid_regex, visibility, created_by, updated_by)
		values ($1, $2, 'dc/corp-prod/ledger', 'prod.internal', $3, 'PUBLIC', 't', 't')`, uuid.NewV7(), name,
		`^spiffe://prod\.internal/ns/ledger/sa/`+n+`-`+w.suffix+`$`); err != nil {
		t.Fatal(err)
	}
	return name
}

func emergency(op, binding, extra string) []byte {
	return []byte(fmt.Sprintf(`{"operation":%q,%s"justification":%q,"incidentReference":"INC0012345"%s}`, op, binding, justification, extra))
}

func breakGlassOf(t *testing.T, o *pgxpool.Pool, name string) (cr *uuid.UUID, open bool) {
	t.Helper()
	if err := o.QueryRow(context.Background(), `select break_glass_cr_id, coalesce(break_glass_expires_at > now() + interval '55 minutes'
		and break_glass_expires_at < now() + interval '65 minutes', false) from bindings where name = $1`, name).Scan(&cr, &open); err != nil {
		t.Fatal(err)
	}
	return cr, open
}

// TestAC31: a break-glass CREATE in an approval-required scope is applied
// at once, its side BREAK_GLASS, the binding open for its TTL, and
// BREAK_GLASS_USED audited (ADR-12).
func TestAC31(t *testing.T) {
	s, o, w, _ := setup(t)
	name := "ledger-bg-" + w.suffix
	r, err := s.BreakGlass(context.Background(), livia, emergency("CREATE",
		`"binding":`+string(body(name, ledgerSource(t, o, w, "a"), w.ledger, "read"))+`,`, `,"ttl":"1h"`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "APPLIED" || r.Kind != changerequests.KindBreakGlass || sides(r) != "TARGET=BREAK_GLASS" {
		t.Fatalf("request %s %s %s", r.Status, r.Kind, sides(r))
	}
	if phase, _, _, _, _ := bindingRow(t, o, name); phase != "PROVISIONING" {
		t.Errorf("phase %s", phase)
	}
	if cr, open := breakGlassOf(t, o, name); cr == nil || *cr != r.ID || !open {
		t.Errorf("break-glass %v open %t", cr, open)
	}
	if n, _ := audited(t, o, name, "BREAK_GLASS_USED"); n != 1 {
		t.Errorf("BREAK_GLASS_USED %d", n)
	}
}

// TestBreakGlassRefusals: the controls of ADR-12 rule 2 and 6, AC-36 and
// AC-38b: people with the role only, justification, incident reference,
// TTL bounds, max_open, maintenance.
func TestBreakGlassRefusals(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	src := ledgerSource(t, o, w, "r")
	create := func() string { return `"binding":` + string(body("ledger-r-"+w.suffix, src, w.ledger, "read")) + `,` }
	robot := caller("spiffe://prod.internal/ns/ci/sa/robot", role(config.RoleBreakGlass, "dc/corp-prod/*"))
	robot.Principal.Name, robot.Principal.SPIFFEID = "", "spiffe://prod.internal/ns/ci/sa/robot"
	for name, tc := range map[string]struct {
		c    changerequests.Caller
		body []byte
		want string
	}{
		"SPIFFE principal":       {robot, emergency("CREATE", create(), ""), "forbidden"},
		"no break_glass role":    {ledgerOp, emergency("CREATE", create(), ""), "forbidden"},
		"short justification":    {livia, []byte(`{"operation":"CREATE",` + create() + `"justification":"down","incidentReference":"INC0012345"}`), "validation-failed"},
		"incident pattern":       {livia, []byte(`{"operation":"CREATE",` + create() + `"justification":"` + justification + `","incidentReference":"CHG1"}`), "validation-failed"},
		"ttl above max_ttl (8h)": {livia, emergency("CREATE", create(), `,"ttl":"9h"`), "validation-failed"},
		"ttl below 5m":           {livia, emergency("CREATE", create(), `,"ttl":"1m"`), "validation-failed"},
		"unknown field":          {livia, emergency("CREATE", create(), `,"inline":{}`), "validation-failed"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.BreakGlass(ctx, tc.c, tc.body); slug(err) != tc.want {
				t.Errorf("%v, want %s", err, tc.want)
			}
		})
	}
	// AC-36: the database refuses a BREAK_GLASS request by a SPIFFE principal
	if _, err := o.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, zone, source_scope,
		target_scope, platform_scope, policy_sha256, distinct_approvers_required, payload, payload_sha256, external_approval_ref,
		break_glass_justification, break_glass_ttl_seconds, requested_by, expires_at)
		values ($1, 'BINDING', $2, 'CREATE', 'BREAK_GLASS', 'ALL', 'prod', 'dc/corp-prod', 'dc/corp-prod', 'dc/corp-prod', repeat('a', 64),
		true, '{}', repeat('b', 64), 'INC0012345', $3, 3600, 'spiffe://prod.internal/x', now() + interval '1 day')`,
		uuid.NewV7(), "x-"+w.suffix, justification); err == nil || !strings.Contains(err.Error(), "chk_break_glass") {
		t.Errorf("SPIFFE break-glass insert: %v", err)
	}

	// AC-38b: refused in maintenance mode, nothing applied
	if _, err := o.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	_, err := s.BreakGlass(ctx, livia, emergency("CREATE", create(), ""))
	_, _ = o.Exec(ctx, "update system_settings set maintenance_mode = false")
	if slug(err) != "maintenance" {
		t.Errorf("in maintenance: %v", err)
	}
	var n int
	if err := o.QueryRow(ctx, "select count(*) from bindings where name = $1", "ledger-r-"+w.suffix).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d bindings applied in maintenance (%v)", n, err)
	}

	// max_open: the policy of dc/corp-prod/* allows one more open change
	var open int
	if err := o.QueryRow(ctx, `select count(distinct r.id) from change_requests r join change_request_sides s on s.change_request_id = r.id
		where r.kind = 'BREAK_GLASS' and r.status = 'APPLIED' and s.basis = 'BREAK_GLASS' and s.ratified_by is null and s.scope like 'dc/corp-prod/%'
		and r.requested_at + make_interval(secs => r.break_glass_ttl_seconds) > now()`).Scan(&open); err != nil {
		t.Fatal(err)
	}
	s.Requests.Policy.BreakGlassPolicyFor("dc/corp-prod/ledger").MaxOpen = open + 1
	if _, err := s.BreakGlass(ctx, livia, emergency("CREATE", create(), "")); err != nil {
		t.Fatal(err)
	}
	other := `"binding":` + string(body("ledger-r2-"+w.suffix, ledgerSource(t, o, w, "r2"), w.ledger, "read")) + `,`
	if _, err := s.BreakGlass(ctx, livia, emergency("CREATE", other, "")); slug(err) != "break-glass-limit" {
		t.Errorf("beyond max_open: %v", err)
	}
}

// TestAC33: a break-glass UPDATE stores the state to revert to; the
// requester cannot ratify (nor can the database be made to), an approver
// can, which clears the expiry and keeps the new revision; a second
// ratification finds nothing open.
func TestAC33(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "ledger-u-" + w.suffix
	active(t, s, o, ledgerOp, name, ledgerSource(t, o, w, "u"), w.ledger, "read", "", ledgerApp)
	r, err := s.BreakGlass(ctx, livia, emergency("UPDATE", `"binding":`+string(body(name, "ledger-src-u-"+w.suffix, w.ledger, "write", `"expectedRevision":1`))+`,`, `,"ttl":"1h"`))
	if err != nil {
		t.Fatal(err)
	}
	var level, revert string
	var revision int64
	if err := o.QueryRow(ctx, `select b.access_level, b.revision, c.revert_payload->>'accessLevel' from bindings b
		join change_requests c on c.id = b.break_glass_cr_id where b.name = $1`, name).Scan(&level, &revision, &revert); err != nil ||
		level != "write" || revision != 2 || revert != "read" {
		t.Fatalf("binding %s r%d, revert to %s (%v)", level, revision, revert, err)
	}
	if _, err := s.Ratify(ctx, caller("livia", role(config.RoleApprover, "dc/*")), r.ID, "", "ok"); slug(err) != "four-eyes-violation" {
		t.Errorf("the requester ratifies: %v", err)
	}
	if _, err := o.Exec(ctx, "update change_request_sides set ratified_by = 'livia', ratified_at = now() where change_request_id = $1", r.ID); err == nil ||
		!strings.Contains(err.Error(), "chk_side_ratification") {
		t.Errorf("the database let the requester ratify: %v", err)
	}
	if _, err := s.Ratify(ctx, ledgerApp, r.ID, "", ""); slug(err) != "validation-failed" {
		t.Errorf("no comment: %v", err)
	}
	if _, err := s.Ratify(ctx, ledgerApp, r.ID, "", "confirmed with the payments lead"); err != nil {
		t.Fatal(err)
	}
	if cr, _ := breakGlassOf(t, o, name); cr != nil {
		t.Errorf("still open: %v", cr)
	}
	if _, _, _, _, revision := bindingRow(t, o, name); revision != 2 {
		t.Errorf("revision %d", revision)
	}
	if n, _ := audited(t, o, name, "BREAK_GLASS_RATIFIED"); n != 1 {
		t.Errorf("BREAK_GLASS_RATIFIED %d", n)
	}
	if _, err := s.Ratify(ctx, ledgerApp, r.ID, "", "again"); slug(err) != "break-glass-not-open" {
		t.Errorf("ratified twice: %v", err)
	}
}

// TestAC35: while a break-glass change is open, a normal UPDATE and a second
// break-glass change are refused; a DELETE is accepted, and applying it
// closes the break-glass change.
func TestAC35(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, src := "ledger-o-"+w.suffix, ledgerSource(t, o, w, "o")
	r, err := s.BreakGlass(ctx, livia, emergency("CREATE", `"binding":`+string(body(name, src, w.ledger, "read"))+`,`, ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, ledgerOp, name, body(name, src, w.ledger, "write", `"expectedRevision":1`)); slug(err) != "break-glass-open" {
		t.Errorf("normal update: %v", err)
	}
	second := emergency("UPDATE", `"binding":`+string(body(name, src, w.ledger, "write", `"expectedRevision":1`))+`,`, "")
	if _, err := s.BreakGlass(ctx, livia, second); slug(err) != "break-glass-open" {
		t.Errorf("second break-glass change: %v", err)
	}
	d, err := s.Delete(ctx, ledgerOp, name, 1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, d, ledgerApp)
	if phase, _, _, _, _ := bindingRow(t, o, name); phase != "DELETING" {
		t.Errorf("phase %s", phase)
	}
	if cr, _ := breakGlassOf(t, o, name); cr != nil {
		t.Errorf("the delete left %s open", r.ID)
	}
}
