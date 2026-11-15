//go:build integration

package sources

import (
	"context"
	"testing"

	"uuid"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pipelineID = "spiffe://cloud.internal/ns/ci/sa/terraform"

// pipeline is a trusted_automation principal of cloud/*: its filings apply
// at once by delegation (ADR-11).
var pipeline = changerequests.Caller{Principal: authz.Principal{SPIFFEID: pipelineID},
	Grants: authz.Grants{{Role: config.RoleTrustedAutomation, Jurisdictions: []string{"cloud/*"}}}}

func managedSource(t *testing.T, s *Service, owner *pgxpool.Pool) Source {
	t.Helper()
	src := source()
	src.Metadata.Name += "-" + lockSuffix()
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from change_requests where resource_type = 'SOURCE' and resource_name = $1", src.Metadata.Name)
		_, _ = owner.Exec(ctx, "delete from sources where name = $1", src.Metadata.Name)
	})
	r, err := s.Create(context.Background(), pipeline, body(t, src, map[string]any{"managed": true, "approvalReference": "CHG-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "APPLIED" {
		t.Fatalf("status %s: a delegated creation applies at once", r.Status)
	}
	return src
}

func managedBy(t *testing.T, owner *pgxpool.Pool, name string) string {
	t.Helper()
	var by string
	if err := owner.QueryRow(context.Background(), "select coalesce(managed_by, '') from sources where name = $1", name).Scan(&by); err != nil {
		t.Fatal(err)
	}
	return by
}

// TestLockAC_M1: only a trusted_automation principal creates a managed
// source, and the filer is its owner.
func TestLockAC_M1(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	src := managedSource(t, s, owner)
	if got := managedBy(t, owner, src.Metadata.Name); got != pipelineID {
		t.Errorf("managed_by %q, want %q", got, pipelineID)
	}
	other := source()
	other.Metadata.Name += "-" + lockSuffix()
	if _, err := s.Create(ctx, alice, body(t, other, map[string]any{"managed": true})); slug(err) != "forbidden" {
		t.Errorf("a person's managed: %v", err)
	}
}

// TestLockAC_M2: whoever is not the owner, with whatever role, is refused,
// and nothing is filed.
func TestLockAC_M2(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	src := managedSource(t, s, owner)
	name := src.Metadata.Name
	upd := map[string]any{"expectedRevision": 1}
	if _, err := s.Update(ctx, alice, name, body(t, src, upd)); slug(err) != "resource-managed" {
		t.Errorf("update by a person: %v", err)
	}
	if _, err := s.SetState(ctx, alice, name, "deprecate", 1, "", nil); slug(err) != "resource-managed" {
		t.Errorf("deprecate by a person: %v", err)
	}
	full := caller("root", config.RoleFullAccess, "*")
	if _, err := s.SetState(ctx, full, name, "retire", 1, "", nil); slug(err) != "resource-managed" {
		t.Errorf("retire with full access: %v", err)
	}
	stranger := changerequests.Caller{Principal: authz.Principal{SPIFFEID: "spiffe://cloud.internal/ns/ci/sa/other"}, Grants: pipeline.Grants}
	if _, err := s.Update(ctx, stranger, name, body(t, src, map[string]any{"expectedRevision": 1, "approvalReference": "CHG-2"})); slug(err) != "resource-managed" {
		t.Errorf("update by another automation: %v", err)
	}
	var n int
	if err := owner.QueryRow(ctx, "select count(*) from change_requests where resource_name = $1", name).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d change requests (%v), want only the creation", n, err)
	}
}

// TestLockAC_M3: the owner changes and releases; after a release a person
// edits.
func TestLockAC_M3(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	src := managedSource(t, s, owner)
	name := src.Metadata.Name
	src.DisplayName = "by the pipeline"
	if r, err := s.Update(ctx, pipeline, name, body(t, src, map[string]any{"expectedRevision": 1, "approvalReference": "CHG-2"})); err != nil || r.Status != "APPLIED" {
		t.Fatalf("owner update: %v", err)
	}
	if got := managedBy(t, owner, name); got != pipelineID {
		t.Errorf("an update that does not say managed keeps the lock: %q", got)
	}
	if r, err := s.Update(ctx, pipeline, name, body(t, src, map[string]any{"expectedRevision": 2, "managed": false, "approvalReference": "CHG-3"})); err != nil || r.Status != "APPLIED" {
		t.Fatalf("release: %v", err)
	}
	if got := managedBy(t, owner, name); got != "" {
		t.Errorf("released, managed_by %q", got)
	}
	src.DisplayName = "by a person"
	if _, err := s.Update(ctx, alice, name, body(t, src, map[string]any{"expectedRevision": 3})); err != nil {
		t.Errorf("a person edits a released source: %v", err)
	}
}

// TestLockAC_M9: the database refuses a change of managed_by that no change
// request makes, and a managed request of a person.
func TestLockAC_M9(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	src := managedSource(t, s, owner)
	if _, err := s.DB.Exec(ctx, "update sources set managed_by = null where name = $1", src.Metadata.Name); err == nil {
		t.Error("the application's role cleared managed_by")
	}
	if _, err := s.DB.Exec(ctx, "update sources set managed_by = 'spiffe://x/y' where name = $1", src.Metadata.Name); err == nil {
		t.Error("the application's role changed managed_by")
	}
	if _, err := owner.Exec(ctx, "update change_requests set managed = false where resource_name = $1", src.Metadata.Name); err == nil {
		t.Error("a change request's managed changed after filing")
	}
	if _, err := s.DB.Exec(ctx, `update sources set managed_by = 'not-a-spiffe-id' where name = $1`, src.Metadata.Name); err == nil {
		t.Error("a managed_by that is no SPIFFE ID")
	}
}

func lockSuffix() string { return uuid.NewV7().String()[24:] }

var root = caller("root", config.RoleFullAccess, "*")

const why = "the pipeline was retired and its owner is gone"

// TestLockAC_M4: adoption needs the sides' consent, a release by an
// administrator is a four-eyes request of people only.
func TestLockAC_M4(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()

	// adoption: the pipeline hands a person's source over to itself; no delegation applies, a person approves.
	src := registered(t, s, owner)
	name := src.Metadata.Name
	r, err := s.Update(ctx, pipeline, name, body(t, src, map[string]any{"expectedRevision": 1, "managed": true, "approvalReference": "CHG-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || r.Sides[0].Basis != changerequests.BasisHuman {
		t.Fatalf("adoption %s, side %+v: the existing sides must agree", r.Status, r.Sides[0])
	}
	if got := managedBy(t, owner, name); got != "" {
		t.Fatalf("managed before the approval: %q", got)
	}
	if _, err := s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if got := managedBy(t, owner, name); got != pipelineID {
		t.Fatalf("adopted, managed_by %q", got)
	}

	// release by administrator
	if _, err := s.Release(ctx, alice, name, 2, why); slug(err) != "forbidden" {
		t.Errorf("an operator releases: %v", err)
	}
	if _, err := s.Release(ctx, pipeline, name, 2, why); slug(err) != "forbidden" {
		t.Errorf("a machine releases: %v", err)
	}
	if _, err := s.Release(ctx, root, name, 2, "retired"); slug(err) != "validation-failed" {
		t.Errorf("a short justification: %v", err)
	}
	r, err = s.Release(ctx, root, name, 2, why)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || r.Consent != changerequests.ConsentAll || r.Sides[0].Basis != changerequests.BasisHuman {
		t.Fatalf("release %s %s %+v", r.Status, r.Consent, r.Sides)
	}
	if _, err := s.Requests.Approve(ctx, root, r.ID, r.PayloadSHA256, "", "ok"); slug(err) == "" {
		t.Error("the administrator approves their own release")
	}
	if got := managedBy(t, owner, name); got != pipelineID {
		t.Fatalf("released before the second person: %q", got)
	}
	if _, err := s.Requests.Approve(ctx, bob, r.ID, r.PayloadSHA256, "", "ok"); err != nil {
		t.Fatal(err)
	}
	if got := managedBy(t, owner, name); got != "" {
		t.Errorf("released, managed_by %q", got)
	}
	if _, err := s.Release(ctx, root, name, 3, why); slug(err) != "validation-failed" {
		t.Errorf("releasing an unmanaged source: %v", err)
	}
}
