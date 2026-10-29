//go:build integration

package bindings

import (
	"context"
	"slices"
	"testing"
	"time"
	"uuid"
)

// TestAC71: a binding is warned once within expiry_warning, a changed
// expiry warns again; past its expiry it is revoked by an applied
// SYSTEM_EXPIRY request during maintenance, its own pending request
// withdrawn first; a busy binding waits (§6.3, INV-25).
func TestAC71(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	var started []uuid.UUID
	s.Start = func(_ context.Context, id uuid.UUID) error { started = append(started, id); return nil }
	at := func(d time.Duration) string {
		return `"expiresAt":"` + time.Now().Add(d).UTC().Format(time.RFC3339) + `"`
	}
	name, busy := "dd-e-"+w.suffix, "dd-b-"+w.suffix
	active(t, s, o, dcOp, name, w.dcSrc, w.dcShared, "read", at(8*24*time.Hour), dcApp)
	active(t, s, o, dcOp, busy, source(t, o, w, "b"), w.dcShared, "read", at(8*24*time.Hour), dcApp)
	var id uuid.UUID
	if err := o.QueryRow(ctx, "select id from bindings where name = $1", name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	warned := func() bool {
		var ok bool
		if err := o.QueryRow(ctx, "select expiry_warned_at is not null from bindings where id = $1", id).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	week := 7 * 24 * time.Hour
	if err := s.WarnExpiry(ctx, week); err != nil || warned() {
		t.Fatalf("warned 8 days ahead (%v)", err)
	}
	if _, err := o.Exec(ctx, "update bindings set expires_at = now() + interval '6 days' where name = any($1)", []string{name, busy}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.WarnExpiry(ctx, week); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := audited(t, o, name, "BINDING_EXPIRY_WARNED"); !warned() || n != 1 {
		t.Errorf("warned %t, %d audits", warned(), n)
	}
	// a changed expiry warns again
	r, err := s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.dcShared, "read", at(5*24*time.Hour), `"expectedRevision":1`))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, dcApp)
	if warned() {
		t.Error("a changed expiry kept the warning")
	}

	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where id = $1", id); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.dcShared, "write", at(5*24*time.Hour), `"expectedRevision":2`))
	if err != nil || pending.Status != "PENDING" {
		t.Fatalf("pending update: %v", err)
	}
	if _, err := o.Exec(ctx, `update bindings set expires_at = now() - interval '1 minute',
		phase = case when name = $2 then 'PROVISIONING'::binding_phase else phase end where name = any($1)`, []string{name, busy}, busy); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	err = s.Expire(ctx)
	_, _ = o.Exec(ctx, "update system_settings set maintenance_mode = false")
	if err != nil {
		t.Fatal(err)
	}
	if phase, workflow, _, _, _ := bindingRow(t, o, name); phase != "DELETING" || workflow != "ligo:delete:"+id.String()+":r2:a3" {
		t.Errorf("expired binding %s %s", phase, workflow)
	}
	if !slices.Contains(started, id) {
		t.Error("the delete workflow was not started")
	}
	if st := status(t, o, pending.ID); st != "WITHDRAWN" {
		t.Errorf("the pending update is %s", st)
	}
	var kind, crStatus, decidedBy, basis string
	if err := o.QueryRow(ctx, `select r.kind, r.status, r.decided_by, s.basis from change_requests r join change_request_sides s
		on s.change_request_id = r.id where r.resource_id = $1 and r.kind = 'SYSTEM_EXPIRY'`, id).Scan(&kind, &crStatus, &decidedBy, &basis); err != nil ||
		crStatus != "APPLIED" || decidedBy != "system:expiry" || basis != "SYSTEM_EXPIRY" {
		t.Errorf("expiry request %s %s %s %s (%v)", kind, crStatus, decidedBy, basis, err)
	}
	if n, _ := audited(t, o, name, "BINDING_EXPIRED"); n != 1 {
		t.Errorf("BINDING_EXPIRED %d", n)
	}
	if phase, _, _, _, _ := bindingRow(t, o, busy); phase != "PROVISIONING" {
		t.Errorf("busy binding %s", phase)
	}
}

// TestAC26: in maintenance mode, filing and approving a change are refused
// with 503 maintenance and nothing changes; declining and withdrawing,
// which start no workflow, remain possible (§10.3).
func TestAC26(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "dd-m-" + w.suffix
	pending, err := s.Create(ctx, dcOp, body(name, w.dcSrc, w.dcShared, "read"))
	if err != nil || pending.Status != "PENDING" {
		t.Fatalf("create: %v", err)
	}
	other, err := s.Create(ctx, dcOp, body("dd-n-"+w.suffix, source(t, o, w, "n"), w.dcShared, "read"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = o.Exec(ctx, "update system_settings set maintenance_mode = false") }()
	if _, err := s.Create(ctx, dcOp, body("dd-x-"+w.suffix, source(t, o, w, "x"), w.dcShared, "read")); slug(err) != "maintenance" {
		t.Errorf("create in maintenance: %v", err)
	}
	if _, err := s.Requests.Approve(ctx, dcApp, pending.ID, pending.PayloadSHA256, "", "ok"); slug(err) != "maintenance" {
		t.Errorf("approve in maintenance: %v", err)
	}
	if st := status(t, o, pending.ID); st != "PENDING" {
		t.Errorf("the refused approval left %s", st)
	}
	if _, err := s.Requests.Decline(ctx, dcApp, pending.ID, "", "not now"); err != nil {
		t.Errorf("decline in maintenance: %v", err)
	}
	if err := s.Requests.Withdraw(ctx, dcOp, other.ID, "later"); err != nil {
		t.Errorf("withdraw in maintenance: %v", err)
	}
	var n int
	if err := o.QueryRow(ctx, "select count(*) from change_requests where resource_name = $1", "dd-x-"+w.suffix).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d requests stored in maintenance (%v)", n, err)
	}
}
