package adminhttp

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// lockExempt lists every write operation that the lock of
// .specs/ligo-managed-resources.md (T-M1) does not refuse to a non-owner,
// with the reason. Any other write operation must go through
// changerequests.Service.Create, where the lock is checked.
var lockExempt = map[string]string{
	"POST /v1/admin/change-requests/{id}/approve":   "a decision on a request, not a change",
	"POST /v1/admin/change-requests/{id}/decline":   "a decision on a request, not a change",
	"POST /v1/admin/change-requests/{id}/withdraw":  "the requester's own request",
	"POST /v1/admin/change-requests/{id}/ratify":    "a decision; ratifying a break-glass change on a managed resource other than a deletion is refused by the service",
	"POST /v1/admin/change-requests/{id}/revert":    "a decision of people",
	"POST /v1/admin/break-glass":                    "emergency path of people: its create is refused while held, and an update is always reverted",
	"POST /v1/admin/holds/{id}/lift":                "the removal of a hold, by a person",
	"POST /v1/admin/{kind}/{name}/release":          "the release by an administrator is the lock's own exit (four eyes, people)",
	"POST /v1/admin/targets/{name}/bindings/revoke": "containment: consent ANY deletions, never blocked",
	"POST /v1/admin/bindings/{name}/retry":          "restarts the workflow of the same definition: no change of the resource",
	"POST /v1/admin/bindings/{name}/rotate":         "restarts the workflow of the same definition: no change of the resource",
	"POST /v1/admin/accounts":                       "accounts are not lockable",
	"POST /v1/admin/accounts/{name}/retire":         "accounts are not lockable",
	"POST /v1/admin/charter/evaluate":               "a dry run",
	"POST /v1/admin/sources/test":                   "a dry run",
	"PUT /v1/admin/maintenance":                     "operations",
	"POST /v1/admin/executors/{id}/recover":         "operations",
	"POST /v1/admin/audit/export":                   "operations",
	"POST /v1/admin/audit/exports":                  "operations",
	"POST /v1/admin/audit/verify":                   "operations",
}

// lockRefuses are the write operations that change a source, a target or a
// binding: a non-owner of a managed one gets 409 resource-managed (§3.2).
var lockRefuses = []string{
	"POST /v1/admin/sources", "PUT /v1/admin/sources/{name}",
	"POST /v1/admin/targets", "PUT /v1/admin/targets/{name}",
	"POST /v1/admin/bindings", "PUT /v1/admin/bindings/{name}", "DELETE /v1/admin/bindings/{name}",
}

// lockRefusesState are the state changes (deprecate, reactivate, retire) of
// sources, targets and a target's access levels, which are updates too.
var lockRefusesState = regexp.MustCompile(`^POST /v1/admin/(sources|targets)/\{name\}(/access-levels/\{level\})?/(deprecate|reactivate|retire)$`)

// TestEveryWriteIsClassified: a new write route fails here until someone says
// whether the lock covers it (T-M1).
func TestEveryWriteIsClassified(t *testing.T) {
	_, doc := openAPI(t)
	for path, item := range at(t, doc, "paths").(map[string]any) {
		for method := range item.(map[string]any) {
			m := strings.ToUpper(method)
			if m == "PARAMETERS" || m == "GET" {
				continue
			}
			op := m + " " + path
			if _, ok := lockExempt[op]; ok || slices.Contains(lockRefuses, op) || lockRefusesState.MatchString(op) || isInstanceOp(path) {
				continue
			}
			if _, ok := lockExempt[strings.NewReplacer("/sources/", "/{kind}/", "/targets/", "/{kind}/", "/bindings/", "/{kind}/").Replace(op)]; ok {
				continue
			}
			t.Errorf("write operation %s is neither covered by the lock nor exempted with a reason (T-M1)", op)
		}
	}
}

// isInstanceOp: platforms, identity providers and secret stores are never
// managed (a lock on an instance is refused by changerequests.Lock).
func isInstanceOp(path string) bool {
	for _, p := range []string{"/platforms", "/identity-providers", "/secret-stores"} {
		if strings.HasPrefix(path, "/v1/admin"+p) {
			return true
		}
	}
	return false
}
