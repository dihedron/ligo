//go:build integration

package bindings

import (
	"context"
	"sync"
	"testing"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/jackc/pgx/v5/pgxpool"
)

// expireBreakGlass makes the open break-glass change of binding name past
// its TTL, and the binding idle.
func expireBreakGlass(t *testing.T, o *pgxpool.Pool, name string) {
	t.Helper()
	ctx := context.Background()
	if _, err := o.Exec(ctx, `update bindings set phase = 'ACTIVE', break_glass_expires_at = now() - interval '1 minute' where name = $1`, name); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Exec(ctx, `update change_requests set requested_at = requested_at - interval '25 hours' where resource_name like $1
		and kind = 'BREAK_GLASS'`, "%"+name[len(name)-12:]); err != nil {
		t.Fatal(err)
	}
}

type reverted struct {
	op, status, decidedBy, basis string
}

func revertOf(t *testing.T, o *pgxpool.Pool, bg uuid.UUID) (reverted, int) {
	t.Helper()
	var r reverted
	var n int
	err := o.QueryRow(context.Background(), `select count(*) over (), c.operation, c.status, coalesce(c.decided_by, ''), s.basis
		from change_requests c join change_request_sides s on s.change_request_id = c.id where c.reverts_cr_id = $1
		order by c.requested_at desc limit 1`, bg).Scan(&n, &r.op, &r.status, &r.decidedBy, &r.basis)
	if err != nil {
		return r, 0
	}
	return r, n
}

// TestAC32: an unratified break-glass CREATE past its TTL is reverted by a
// SYSTEM_REVERT DELETE, even in maintenance mode (AC-38); once the binding
// is gone, its inline source is retired by a SYSTEM_REVERT source change
// (AC-75). Nothing is reverted twice.
func TestAC32(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	src, name := "dc-inl-src-"+w.suffix, "dc-inl-"+w.suffix
	inline := `"inlineSource":{"metadata":{"name":"` + src + `"},"identity":{"trustDomain":"prod.internal",` +
		`"svidRegex":"^spiffe://prod\\.internal/ns/inline/sa/` + w.suffix + `$","sampleSpiffeIds":["spiffe://prod.internal/ns/inline/sa/` + w.suffix + `"]},` +
		`"visibility":{"mode":"PRIVATE"}},`
	bg, err := s.BreakGlass(ctx, livia, emergency("CREATE", inline+`"binding":`+string(body(name, src, w.dcShared, "read"))+`,`, ""))
	if err != nil {
		t.Fatal(err)
	}
	expireBreakGlass(t, o, name)
	if _, err := o.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	err = s.RevertExpired(ctx)
	_, _ = o.Exec(ctx, "update system_settings set maintenance_mode = false")
	if err != nil {
		t.Fatal(err)
	}
	if r, n := revertOf(t, o, bg.ID); n != 1 || r != (reverted{"DELETE", "APPLIED", changerequests.RevertApprover, "SYSTEM_REVERT"}) {
		t.Fatalf("revert %+v (%d)", r, n)
	}
	if phase, _, _, _, _ := bindingRow(t, o, name); phase != "DELETING" {
		t.Errorf("phase %s", phase)
	}
	if n, _ := audited(t, o, name, "BREAK_GLASS_REVERT_STARTED"); n != 1 {
		t.Errorf("BREAK_GLASS_REVERT_STARTED %d", n)
	}
	if err := s.RevertExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if _, n := revertOf(t, o, bg.ID); n != 1 {
		t.Errorf("reverted %d times", n)
	}

	// the source stays while its binding exists, then is retired
	if err := s.RetireInlineSources(ctx); err != nil {
		t.Fatal(err)
	}
	state := func() string {
		var st string
		if err := o.QueryRow(ctx, "select state from sources where name = $1", src).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := state(); st != "ACTIVE" {
		t.Errorf("source %s while its binding is deleted", st)
	}
	if _, err := o.Exec(ctx, "delete from bindings where name = $1", name); err != nil { // the delete workflow completed
		t.Fatal(err)
	}
	if err := s.RetireInlineSources(ctx); err != nil {
		t.Fatal(err)
	}
	if st := state(); st != "RETIRED" {
		t.Errorf("source %s after the revert", st)
	}
	if n, _ := audited(t, o, src, "SOURCE_RETIRED"); n != 1 {
		t.Errorf("SOURCE_RETIRED %d", n)
	}
	if err := s.OverdueReviews(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := audited(t, o, name, "BREAK_GLASS_REVIEW_OVERDUE"); n != 0 {
		t.Error("a reverted change is overdue")
	}
}

// TestAC34: an unratified break-glass UPDATE past its TTL is reverted by a
// SYSTEM_REVERT UPDATE to the previous state, as a new revision.
func TestAC34(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, src := "ledger-u-"+w.suffix, ledgerSource(t, o, w, "u")
	active(t, s, o, ledgerOp, name, src, w.ledger, "read", "", ledgerApp)
	bg, err := s.BreakGlass(ctx, livia, emergency("UPDATE", `"binding":`+string(body(name, src, w.ledger, "write", `"expectedRevision":1`))+`,`, ""))
	if err != nil {
		t.Fatal(err)
	}
	expireBreakGlass(t, o, name)
	if err := s.RevertExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if r, n := revertOf(t, o, bg.ID); n != 1 || r.op != "UPDATE" || r.status != "APPLIED" {
		t.Fatalf("revert %+v (%d)", r, n)
	}
	var level string
	var revision int64
	var open bool
	if err := o.QueryRow(ctx, "select access_level, revision, break_glass_cr_id is not null from bindings where name = $1", name).Scan(&level, &revision, &open); err != nil ||
		level != "read" || revision != 3 || open {
		t.Errorf("binding %s r%d open %t (%v)", level, revision, open, err)
	}
}

// TestRevertFailed: a revert payload that no longer validates is a failed
// revert: recorded FAILED_TO_APPLY, BREAK_GLASS_REVERT_FAILED audited, the
// change still open and not retried by the sweeper; an operator may retry.
func TestRevertFailed(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, src := "ledger-f-"+w.suffix, ledgerSource(t, o, w, "f")
	active(t, s, o, ledgerOp, name, src, w.ledger, "read", "", ledgerApp)
	bg, err := s.BreakGlass(ctx, livia, emergency("UPDATE", `"binding":`+string(body(name, src, w.ledger, "write", `"expectedRevision":1`))+`,`, ""))
	if err != nil {
		t.Fatal(err)
	}
	expireBreakGlass(t, o, name)
	if _, err := o.Exec(ctx, "delete from target_access_levels where target_id = $1 and name = 'read'", w.ledgerID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.RevertExpired(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if r, n := revertOf(t, o, bg.ID); n != 1 || r.status != "FAILED_TO_APPLY" {
		t.Fatalf("revert %+v (%d)", r, n)
	}
	if n, _ := audited(t, o, name, "BREAK_GLASS_REVERT_FAILED"); n != 1 {
		t.Errorf("BREAK_GLASS_REVERT_FAILED %d", n)
	}
	if cr, _ := breakGlassOf(t, o, name); cr == nil {
		t.Error("the failed revert closed the change")
	}
	if _, err := s.RevertNow(ctx, ledgerApp, bg.ID); slug(err) != "validation-failed" {
		t.Errorf("retry: %v", err)
	}
	if _, n := revertOf(t, o, bg.ID); n != 2 {
		t.Errorf("%d reverts after the retry", n)
	}
}

// TestAC38a: ratify and revert both lock the binding first: exactly one
// wins, the other gets break-glass-not-open.
func TestAC38a(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	for i, first := range []string{"ratify", "revert", "race"} {
		name, src := "ledger-a"+string(rune('0'+i))+"-"+w.suffix, ledgerSource(t, o, w, "a"+string(rune('0'+i)))
		bg, err := s.BreakGlass(ctx, livia, emergency("CREATE", `"binding":`+string(body(name, src, w.ledger, "read"))+`,`, ""))
		if err != nil {
			t.Fatal(err)
		}
		expireBreakGlass(t, o, name)
		var ratifyErr, revertErr error
		ratify := func() { _, ratifyErr = s.Ratify(ctx, ledgerApp, bg.ID, "", "confirmed") }
		revert := func() { _, revertErr = s.RevertNow(ctx, livia, bg.ID) }
		switch first {
		case "ratify":
			ratify()
			revert()
		case "revert":
			revert()
			ratify()
		default:
			var wg sync.WaitGroup
			wg.Go(ratify)
			wg.Go(revert)
			wg.Wait()
		}
		lost := 0
		for _, err := range []error{ratifyErr, revertErr} {
			if slug(err) == "break-glass-not-open" {
				lost++
			} else if err != nil {
				t.Errorf("%s: %v", first, err)
			}
		}
		if lost != 1 {
			t.Errorf("%s: ratify %v, revert %v", first, ratifyErr, revertErr)
		}
	}
}

// TestAC38c: a break-glass CREATE whose binding is deleted normally is not
// reverted; past its TTL, unratified, its review is overdue, once.
func TestAC38c(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, src := "ledger-c-"+w.suffix, ledgerSource(t, o, w, "c")
	bg, err := s.BreakGlass(ctx, livia, emergency("CREATE", `"binding":`+string(body(name, src, w.ledger, "read"))+`,`, ""))
	if err != nil {
		t.Fatal(err)
	}
	expireBreakGlass(t, o, name)
	d, err := s.Delete(ctx, ledgerOp, name, 1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, d, ledgerApp)
	if _, err := o.Exec(ctx, "delete from bindings where name = $1", name); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.RevertExpired(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.OverdueReviews(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, n := revertOf(t, o, bg.ID); n != 0 {
		t.Errorf("%d reverts", n)
	}
	if n, by := audited(t, o, name, "BREAK_GLASS_REVIEW_OVERDUE"); n != 1 || by != bg.ID {
		t.Errorf("BREAK_GLASS_REVIEW_OVERDUE %d (%s)", n, by)
	}
}

// TestWarnBreakGlass: BREAK_GLASS_EXPIRING once within warn_before (1h for
// dc/corp-prod/*).
func TestWarnBreakGlass(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, src := "ledger-w-"+w.suffix, ledgerSource(t, o, w, "w")
	if _, err := s.BreakGlass(ctx, livia, emergency("CREATE", `"binding":`+string(body(name, src, w.ledger, "read"))+`,`, `,"ttl":"2h"`)); err != nil {
		t.Fatal(err)
	}
	if err := s.WarnBreakGlass(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := audited(t, o, name, "BREAK_GLASS_EXPIRING"); n != 0 {
		t.Fatal("warned 2h ahead")
	}
	if _, err := o.Exec(ctx, "update bindings set break_glass_expires_at = now() + interval '50 minutes' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.WarnBreakGlass(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := audited(t, o, name, "BREAK_GLASS_EXPIRING"); n != 1 {
		t.Errorf("BREAK_GLASS_EXPIRING %d", n)
	}
}
