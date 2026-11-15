//go:build integration

package bindings

import (
	"context"
	"testing"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
)

const pipelineID = "spiffe://prod.internal/ns/ci/sa/terraform"

// pipeline is a trusted_automation principal of the data centre: its filings
// apply at once by delegation (ADR-11).
var pipeline = changerequests.Caller{Principal: authz.Principal{SPIFFEID: pipelineID},
	Grants: authz.Grants{role(config.RoleTrustedAutomation, "dc/corp-prod", "dc/corp-prod/*")}}

func lockOwner(t *testing.T, s *Service, name string) string {
	t.Helper()
	var by string
	if err := s.DB.QueryRow(context.Background(), "select coalesce(managed_by, '') from bindings where name = $1", name).Scan(&by); err != nil {
		t.Fatal(err)
	}
	return by
}

// TestLock covers AC-M1 to AC-M3 and AC-M9 for bindings, and that
// containment (consent ANY) is not blocked (§3.4).
func TestLock(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "ledger-lock-" + w.suffix

	if _, err := s.Create(ctx, ledgerOp, body(name, w.dcSrc, w.ledger, "read", `"managed":true`)); slug(err) != "forbidden" { // AC-M1
		t.Errorf("a person's managed: %v", err)
	}
	r, err := s.Create(ctx, pipeline, body(name, w.dcSrc, w.ledger, "read", `"managed":true`, `"approvalReference":"CHG-1"`))
	if err != nil || r.Status != "APPLIED" {
		t.Fatalf("managed creation: %+v, %v", r, err)
	}
	if got := lockOwner(t, s, name); got != pipelineID {
		t.Fatalf("managed_by %q", got)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}

	// AC-M2: a non-owner is refused, whatever its role, and nothing is filed.
	if _, err := s.Update(ctx, ledgerOp, name, body(name, w.dcSrc, w.ledger, "write", `"expectedRevision":1`)); slug(err) != "resource-managed" {
		t.Errorf("update by a person: %v", err)
	}
	full := caller("root", role(config.RoleFullAccess, "*"))
	if _, err := s.Update(ctx, full, name, body(name, w.dcSrc, w.ledger, "write", `"expectedRevision":1`)); slug(err) != "resource-managed" {
		t.Errorf("update with full access: %v", err)
	}
	var n int
	if err := o.QueryRow(ctx, "select count(*) from change_requests where resource_name = $1", name).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d change requests (%v), want only the creation", n, err)
	}

	// Containment is never blocked: the platform owner files a revocation (consent ANY).
	r, err = s.Delete(ctx, dcOp, name, 1, "", nil)
	if err != nil || r.Consent != changerequests.ConsentAny {
		t.Fatalf("containment: %+v, %v", r, err)
	}
	if err := s.Requests.Withdraw(ctx, dcOp, r.ID, "test"); err != nil {
		t.Fatal(err)
	}

	// AC-M3: the owner changes (keeping the lock) and releases; then a person edits.
	if r, err := s.Update(ctx, pipeline, name, body(name, w.dcSrc, w.ledger, "write", `"expectedRevision":1`, `"approvalReference":"CHG-2"`)); err != nil || r.Status != "APPLIED" {
		t.Fatalf("owner update: %+v, %v", r, err)
	}
	if got := lockOwner(t, s, name); got != pipelineID {
		t.Errorf("an update that does not say managed keeps the lock: %q", got)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Update(ctx, pipeline, name, body(name, w.dcSrc, w.ledger, "write", `"expectedRevision":2`, `"managed":false`, `"approvalReference":"CHG-3"`)); err != nil || r.Status != "APPLIED" {
		t.Fatalf("release: %+v, %v", r, err)
	}
	if got := lockOwner(t, s, name); got != "" {
		t.Errorf("released, managed_by %q", got)
	}

	// AC-M9: the application's role cannot move the lock on its own.
	if _, err := s.DB.Exec(ctx, "update bindings set managed_by = 'spiffe://x/y' where name = $1", name); err == nil {
		t.Error("the application's role set managed_by")
	}
}

var root = caller("root", role(config.RoleFullAccess, "*"))

const why = "the pipeline was retired and its owner is gone"

// TestLockAC_M4: adoption needs the sides' consent, a release by an
// administrator is a four-eyes request of people only.
func TestLockAC_M4(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name, source := "ledger-adopt-"+w.suffix, ledgerSource(t, o, w, "a")
	active(t, s, o, ledgerOp, name, source, w.ledger, "read", "", ledgerApp)

	r, err := s.Update(ctx, pipeline, name, body(name, source, w.ledger, "read", `"expectedRevision":1`, `"managed":true`, `"approvalReference":"CHG-1"`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || r.Sides[0].Basis != changerequests.BasisHuman {
		t.Fatalf("adoption %s, sides %s: the existing sides must agree", r.Status, sides(r))
	}
	approve(t, s, r, ledgerApp)
	if got := lockOwner(t, s, name); got != pipelineID {
		t.Fatalf("adopted, managed_by %q", got)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	rev := func() int64 { _, _, _, _, r := bindingRow(t, o, name); return r }

	if _, err := s.Release(ctx, ledgerOp, name, rev(), why); slug(err) != "forbidden" {
		t.Errorf("an operator releases: %v", err)
	}
	if _, err := s.Release(ctx, pipeline, name, rev(), why); slug(err) != "forbidden" {
		t.Errorf("a machine releases: %v", err)
	}
	if _, err := s.Release(ctx, root, name, rev()+1, why); slug(err) != "revision-conflict" {
		t.Errorf("a stale revision: %v", err)
	}
	if _, err := s.Release(ctx, root, name, rev(), "retired"); slug(err) != "validation-failed" {
		t.Errorf("a short justification: %v", err)
	}
	r, err = s.Release(ctx, root, name, rev(), why)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || r.Consent != changerequests.ConsentAll || r.Sides[0].Basis != changerequests.BasisHuman {
		t.Fatalf("release %s %s %s", r.Status, r.Consent, sides(r))
	}
	if _, err := s.Requests.Approve(ctx, root, r.ID, r.PayloadSHA256, "", "ok"); slug(err) == "" {
		t.Error("the administrator approves their own release")
	}
	if got := lockOwner(t, s, name); got != pipelineID {
		t.Fatalf("released before the second person: %q", got)
	}
	approve(t, s, r, ledgerApp)
	if got := lockOwner(t, s, name); got != "" {
		t.Errorf("released, managed_by %q", got)
	}
	if _, err := s.Release(ctx, root, name, rev(), why); slug(err) != "validation-failed" {
		t.Errorf("releasing an unmanaged binding: %v", err)
	}
}
