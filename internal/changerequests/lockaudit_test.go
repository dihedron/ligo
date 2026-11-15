package changerequests

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestLockAudit: what a lock set or released says, and that a lock that does
// not change hands says nothing.
func TestLockAudit(t *testing.T) {
	on, off := true, false
	const owner, other = "spiffe://x/ns/ci/sa/a", "spiffe://x/ns/ci/sa/b"
	for _, tc := range []struct {
		name   string
		r      Request
		cur    string
		action string
	}{
		{"created managed", Request{Managed: &on, RequestedBy: owner, Operation: "CREATE"}, "", "RESOURCE_MANAGED"},
		{"adopted", Request{Managed: &on, RequestedBy: owner, Operation: "UPDATE"}, "", "RESOURCE_MANAGED"},
		{"taken over from another owner", Request{Managed: &on, RequestedBy: owner, Operation: "UPDATE"}, other, "RESOURCE_MANAGED"},
		{"the owner keeps it", Request{Managed: &on, RequestedBy: owner, Operation: "UPDATE"}, owner, ""},
		{"released by the owner", Request{Managed: &off, RequestedBy: owner, Operation: "UPDATE"}, owner, "RESOURCE_RELEASED"},
		{"released by an administrator", Request{Managed: &off, RequestedBy: "root", Operation: "UPDATE", ReleaseJustification: "the pipeline was retired"}, other, "RESOURCE_RELEASED_BY_ADMIN"},
		{"released while unmanaged", Request{Managed: &off, RequestedBy: owner, Operation: "UPDATE"}, "", ""},
		{"says nothing of the lock", Request{RequestedBy: owner, Operation: "UPDATE"}, owner, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := lockAudit(&tc.r, tc.cur)
			switch {
			case e == nil && tc.action != "":
				t.Errorf("no entry, want %s", tc.action)
			case e != nil && e.Action != tc.action:
				t.Errorf("entry %s, want %q", e.Action, tc.action)
			case e != nil && !json.Valid(e.Snapshot):
				t.Errorf("snapshot %s", e.Snapshot)
			}
		})
	}
}

// TestAuditable: one audited refusal for each principal and resource in a
// window, and again after it.
func TestAuditable(t *testing.T) {
	now := time.Now()
	if !auditable("a\x00SOURCE\x00s1", now) || auditable("a\x00SOURCE\x00s1", now.Add(violationWindow/2)) {
		t.Error("the second refusal in a window was audited, or the first was not")
	}
	if !auditable("b\x00SOURCE\x00s1", now) || !auditable("a\x00SOURCE\x00s2", now) {
		t.Error("another principal or resource shares the window")
	}
	if !auditable("a\x00SOURCE\x00s1", now.Add(violationWindow)) {
		t.Error("not audited again after the window")
	}
}

// TestAuditableForgets: what is out of its window is forgotten when the table is large.
func TestAuditableForgets(t *testing.T) {
	now := time.Now()
	recentViolations.Lock()
	for i := range 4096 {
		recentViolations.at[fmt.Sprintf("old-%d", i)] = now.Add(-2 * violationWindow)
	}
	recentViolations.Unlock()
	if !auditable("fresh", now) {
		t.Fatal("a new key was not audited")
	}
	recentViolations.Lock()
	defer recentViolations.Unlock()
	if _, ok := recentViolations.at["old-0"]; ok || len(recentViolations.at) > 4096 {
		t.Errorf("%d keys remain, old ones included: %v", len(recentViolations.at), ok)
	}
}
