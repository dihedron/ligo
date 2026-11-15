//go:build integration

package bindings

import (
	"context"
	"github.com/dihedron/ligo/internal/audit"
	"testing"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/jackc/pgx/v5/pgxpool"
)

// managedBinding has the pipeline create a managed, ACTIVE binding of a
// fresh ledger source to the ledger target, and returns its name and source.
func managedBinding(t *testing.T, s *Service, o *pgxpool.Pool, w *world, n string) (name, source string) {
	t.Helper()
	name, source = "ledger-m-"+n+"-"+w.suffix, ledgerSource(t, o, w, n)
	t.Cleanup(func() { // before the world's: a hold references its change request
		_, _ = o.Exec(context.Background(), "delete from managed_holds where binding_name like $1", "%"+w.suffix+"%")
	})
	r, err := s.Create(context.Background(), pipeline, body(name, source, w.ledger, "read", `"managed":true`, `"approvalReference":"CHG-1"`))
	if err != nil || r.Status != "APPLIED" {
		t.Fatalf("managed creation: %+v, %v", r, err)
	}
	if _, err := o.Exec(context.Background(), "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	return name, source
}

type hold struct {
	n                                       int
	basis, owner, deletedBy, liftedBy, lift string
}

func holdOf(t *testing.T, o *pgxpool.Pool, name string) hold {
	t.Helper()
	var h hold
	err := o.QueryRow(context.Background(), `select count(*), coalesce(max(basis), ''), coalesce(max(managed_by), ''), coalesce(max(deleted_by), ''),
		coalesce(max(lifted_by), ''), coalesce(max(lift_basis), '') from managed_holds where binding_name = $1`, name).
		Scan(&h.n, &h.basis, &h.owner, &h.deletedBy, &h.liftedBy, &h.lift)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestHoldContainment (AC-M5): the platform owner revokes a managed binding
// with consent ANY, and a hold is left; the owner's own deletion leaves none.
func TestHoldContainment(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, _ := managedBinding(t, s, o, w, "c")
	r, err := s.Delete(ctx, dcOp, name, 1, "", nil)
	if err != nil || r.Consent != changerequests.ConsentAny {
		t.Fatalf("containment: %+v, %v", r, err)
	}
	approve(t, s, r, dcApp)
	if h := holdOf(t, o, name); h != (hold{1, "CONTAINMENT", pipelineID, "dino", "", ""}) {
		t.Errorf("hold %+v", h)
	}
	if n, _ := audited(t, o, name, "HOLD_CREATED"); n != 1 {
		t.Errorf("HOLD_CREATED %d", n)
	}

	own, _ := managedBinding(t, s, o, w, "o")
	if r, err := s.Delete(ctx, pipeline, own, 1, "CHG-2", nil); err != nil || r.Status != "APPLIED" {
		t.Fatalf("owner delete: %+v, %v", r, err)
	}
	if h := holdOf(t, o, own); h.n != 0 {
		t.Errorf("the owner's own deletion left a hold: %+v", h)
	}
}

// TestHoldRefusesAndLifts (AC-M7): while a hold stands, nobody creates the
// binding again, the pipeline and people alike; only a person who approves a
// side lifts it, with a comment.
func TestHoldRefusesAndLifts(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, source := managedBinding(t, s, o, w, "h")
	r, err := s.Delete(ctx, dcOp, name, 1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, dcApp)
	if _, err := o.Exec(ctx, "delete from bindings where name = $1", name); err != nil { // the delete workflow ended
		t.Fatal(err)
	}
	again := body(name+"-2", source, w.ledger, "read")
	if _, err := s.Create(ctx, ledgerOp, again); slug(err) != "resource-held" {
		t.Errorf("a person re-creates: %v", err)
	}
	if _, err := s.Create(ctx, pipeline, body(name+"-2", source, w.ledger, "read", `"managed":true`, `"approvalReference":"CHG-3"`)); slug(err) != "resource-held" {
		t.Errorf("the pipeline re-creates: %v", err)
	}
	if _, err := s.Create(ctx, ledgerOp, body(name, ledgerSource(t, o, w, "x"), w.ledger, "read")); slug(err) != "resource-held" {
		t.Errorf("the held name on another source: %v", err)
	}
	var id string
	if err := o.QueryRow(ctx, "select id::text from managed_holds where binding_name = $1", name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := s.LiftHold(ctx, ledgerOp, id, "I want it back"); slug(err) != "forbidden" {
		t.Errorf("an operator lifts: %v", err)
	}
	if err := s.LiftHold(ctx, pipeline, id, "the pipeline lifts"); slug(err) != "forbidden" {
		t.Errorf("the pipeline lifts: %v", err)
	}
	if err := s.LiftHold(ctx, ledgerApp, id, " "); slug(err) != "validation-failed" {
		t.Errorf("a lift without a comment: %v", err)
	}
	if h := holdOf(t, o, name); h.liftedBy != "" {
		t.Fatalf("lifted without a person: %+v", h)
	}
	// an open hold holds the audit pruning back at the entry that created it
	var created, floor int64
	if err := o.QueryRow(ctx, "select min(id) from audit_log where action = 'HOLD_CREATED' and resource_name = $1", name).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if err := o.QueryRow(ctx, "select "+audit.OpenHoldFloor).Scan(&floor); err != nil || floor > created {
		t.Errorf("floor %d with an open hold created at %d (%v)", floor, created, err)
	}
	if err := s.LiftHold(ctx, ledgerApp, id, "restored after the review"); err != nil {
		t.Fatal(err)
	}
	if h := holdOf(t, o, name); h.liftedBy != "bob" || h.lift != "PERSON" {
		t.Errorf("hold %+v", h)
	}
	if err := s.LiftHold(ctx, ledgerApp, id, "again"); slug(err) != "resource-held" {
		t.Errorf("lifted twice: %v", err)
	}
	if n, _ := audited(t, o, name, "HOLD_LIFTED"); n != 1 {
		t.Errorf("HOLD_LIFTED %d", n)
	}
	var other int64
	if err := o.QueryRow(ctx, "select "+audit.OpenHoldFloor).Scan(&other); err != nil || other <= created {
		t.Errorf("floor %d after the lift, was %d (%v)", other, floor, err)
	}
	if _, err := s.Create(ctx, pipeline, body(name+"-2", source, w.ledger, "read", `"managed":true`, `"approvalReference":"CHG-3"`)); err != nil {
		t.Errorf("after the lift: %v", err)
	}
}

// TestBreakGlassOnManaged (AC-M6): a break-glass UPDATE of a managed binding
// is allowed, cannot be ratified, and is reverted at its TTL.
func TestBreakGlassOnManaged(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, source := managedBinding(t, s, o, w, "b")
	r, err := s.BreakGlass(ctx, livia, emergency("UPDATE", `"binding":`+string(body(name, source, w.ledger, "write", `"expectedRevision":1`))+`,`, `,"ttl":"1h"`))
	if err != nil {
		t.Fatal(err)
	}
	if by := lockOwner(t, s, name); by != pipelineID {
		t.Errorf("a break-glass change moved the lock to %q", by)
	}
	if _, err := s.Ratify(ctx, ledgerApp, r.ID, "", "keep it"); slug(err) != "resource-managed" {
		t.Errorf("ratify: %v", err)
	}
	if cr, _ := breakGlassOf(t, o, name); cr == nil || *cr != r.ID {
		t.Errorf("the change is no longer open: %v", cr)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	expireBreakGlass(t, o, name)
	if err := s.RevertExpired(ctx); err != nil {
		t.Fatal(err)
	}
	var level string
	if err := o.QueryRow(ctx, "select access_level from bindings where name = $1", name).Scan(&level); err != nil || level != "read" {
		t.Errorf("level %q after the TTL (%v), want read", level, err)
	}
}

// TestBreakGlassDeleteOnManaged (AC-M6, AC-M7): an emergency DELETE of a
// managed binding stays final and leaves a hold, which blocks a break-glass
// CREATE of the name; ratifying the DELETE ends the hold.
func TestBreakGlassDeleteOnManaged(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, source := managedBinding(t, s, o, w, "d")
	r, err := s.BreakGlass(ctx, livia, emergency("DELETE", `"name":"`+name+`","expectedRevision":1,`, ""))
	if err != nil {
		t.Fatal(err)
	}
	if h := holdOf(t, o, name); h.n != 1 || h.basis != "BREAK_GLASS" || h.owner != pipelineID {
		t.Fatalf("hold %+v", h)
	}
	if _, err := o.Exec(ctx, "delete from bindings where name = $1", name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BreakGlass(ctx, livia, emergency("CREATE", `"binding":`+string(body(name, source, w.ledger, "read"))+`,`, "")); slug(err) != "resource-held" {
		t.Errorf("a break-glass create of a held name: %v", err)
	}
	if _, err := s.Ratify(ctx, ledgerApp, r.ID, "", "the revocation was right"); err != nil {
		t.Fatal(err)
	}
	if h := holdOf(t, o, name); h.liftedBy != "" && len(r.Sides) > 1 {
		t.Errorf("the hold ended before every side ratified: %+v", h)
	}
	if h := holdOf(t, o, name); h.liftedBy == "" { // the other sides, if any
		if _, err := s.Ratify(ctx, dcApp, r.ID, "", "the revocation was right"); err != nil {
			t.Fatal(err)
		}
	}
	if h := holdOf(t, o, name); h.liftedBy != "bob" && h.liftedBy != "dora" || h.lift != "RATIFIED" {
		t.Errorf("hold after the ratification: %+v", h)
	}
}

// TestLockSetBeforeApply (AC-M8): a person's update filed while the resource
// was unmanaged fails to apply once a lock stands.
func TestLockSetBeforeApply(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, source := "ledger-race-"+w.suffix, ledgerSource(t, o, w, "r")
	active(t, s, o, ledgerOp, name, source, w.ledger, "read", "", ledgerApp)
	r, err := s.Update(ctx, ledgerOp, name, body(name, source, w.ledger, "write", `"expectedRevision":1`))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"alter table bindings disable trigger trg_bindings_managed_by",
		"update bindings set managed_by = '" + pipelineID + "' where name = '" + name + "'",
		"alter table bindings enable trigger trg_bindings_managed_by"} {
		if _, err := o.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = s.Requests.Approve(ctx, ledgerApp, r.ID, r.PayloadSHA256, "", "ok")
	var status, apply string
	if err := o.QueryRow(ctx, "select status, coalesce(apply_error, '') from change_requests where id = $1", r.ID).Scan(&status, &apply); err != nil {
		t.Fatal(err)
	}
	if status != "FAILED_TO_APPLY" || apply == "" {
		t.Errorf("status %s (%s), want FAILED_TO_APPLY", status, apply)
	}
	var level string
	if err := o.QueryRow(ctx, "select access_level from bindings where name = $1", name).Scan(&level); err != nil || level != "read" {
		t.Errorf("level %q (%v): the person's update applied to a managed binding", level, err)
	}
}
