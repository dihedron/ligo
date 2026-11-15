//go:build integration

package targets

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
)

const pipelineID = "spiffe://corp.internal/ns/ci/sa/terraform"

// pipeline is a trusted_automation principal of the ledger and its platform:
// its filings apply at once by delegation (ADR-11).
var pipeline = changerequests.Caller{Principal: authz.Principal{SPIFFEID: pipelineID},
	Grants: authz.Grants{{Role: config.RoleTrustedAutomation, Jurisdictions: []string{"dc/corp-prod", "dc/corp-prod/*"}}}}

func lockBody(t *testing.T, tg Target, extra map[string]any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body(t, tg), &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range extra {
		m[k] = v
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func managedBy(t *testing.T, s *Service, name string) string {
	t.Helper()
	var by string
	if err := s.DB.QueryRow(context.Background(), "select coalesce(managed_by, '') from targets where name = $1", name).Scan(&by); err != nil {
		t.Fatal(err)
	}
	return by
}

// TestLock covers AC-M1 to AC-M3 and AC-M9 for targets.
func TestLock(t *testing.T) {
	s, owner := setup(t)
	ctx := context.Background()
	tg := ledger()
	unique(t, owner, &tg)
	name := tg.Metadata.Name

	if _, err := s.Create(ctx, alice, lockBody(t, tg, map[string]any{"managed": true})); slug(err) != "forbidden" { // AC-M1
		t.Errorf("a person's managed: %v", err)
	}
	r, err := s.Create(ctx, pipeline, lockBody(t, tg, map[string]any{"managed": true, "approvalReference": "CHG-1"}))
	if err != nil || r.Status != "APPLIED" {
		t.Fatalf("managed creation: %+v, %v", r, err)
	}
	if got := managedBy(t, s, name); got != pipelineID {
		t.Fatalf("managed_by %q", got)
	}

	// AC-M2: a non-owner is refused, whatever its role, and nothing is filed.
	full := caller("root", config.RoleFullAccess, "*")
	if _, err := s.Update(ctx, alice, name, lockBody(t, tg, map[string]any{"expectedRevision": 1})); slug(err) != "resource-managed" {
		t.Errorf("update by a person: %v", err)
	}
	if _, err := s.SetState(ctx, full, name, "retire", 1, "", nil); slug(err) != "resource-managed" {
		t.Errorf("retire with full access: %v", err)
	}
	var n int
	if err := owner.QueryRow(ctx, "select count(*) from change_requests where resource_name = $1", name).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d change requests (%v), want only the creation", n, err)
	}

	// AC-M3: the owner changes (keeping the lock) and releases; then a person edits.
	tg.DisplayName = "by the pipeline"
	if r, err := s.Update(ctx, pipeline, name, lockBody(t, tg, map[string]any{"expectedRevision": 1, "approvalReference": "CHG-2"})); err != nil || r.Status != "APPLIED" {
		t.Fatalf("owner update: %+v, %v", r, err)
	}
	if got := managedBy(t, s, name); got != pipelineID {
		t.Errorf("an update that does not say managed keeps the lock: %q", got)
	}
	if r, err := s.Update(ctx, pipeline, name, lockBody(t, tg, map[string]any{"expectedRevision": 2, "managed": false, "approvalReference": "CHG-3"})); err != nil || r.Status != "APPLIED" {
		t.Fatalf("release: %+v, %v", r, err)
	}
	if got := managedBy(t, s, name); got != "" {
		t.Errorf("released, managed_by %q", got)
	}

	// AC-M9: the application's role cannot move the lock on its own.
	if _, err := s.DB.Exec(ctx, "update targets set managed_by = 'spiffe://x/y' where name = $1", name); err == nil {
		t.Error("the application's role set managed_by")
	}
}
