package changerequests

import (
	"testing"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/config"
)

const (
	pipeline = "spiffe://example.com/ns/ci/sa/terraform"
	other    = "spiffe://example.com/ns/ci/sa/other"
)

func spiffeCaller(id string, grants ...authz.Grant) Caller {
	return Caller{Principal: authz.Principal{SPIFFEID: id}, Grants: grants}
}

// TestLock is the decision table of .specs/ligo-managed-resources.md §3.1 to
// §3.4: only the owner changes a managed resource, containment excepted;
// only a trusted_automation principal sets the lock.
func TestLock(t *testing.T) {
	person := Caller{Principal: authz.Principal{Name: "alice"}, Grants: authz.Grants{grant(config.RoleFullAccess, "*")}}
	owner := spiffeCaller(pipeline, grant(config.RoleTrustedAutomation, "dc/corp-prod/*"))
	stranger := spiffeCaller(other, grant(config.RoleTrustedAutomation, "dc/corp-prod/*"))
	machine := spiffeCaller(other, grant(config.RoleOperator, "dc/corp-prod/*"))
	on := func(v bool) *bool { return &v }

	for _, tc := range []struct {
		name string
		c    Caller
		r    Request
		want string
	}{
		{"unmanaged: anyone", person, Request{Operation: "UPDATE"}, ""},
		{"owner updates", owner, Request{Operation: "UPDATE", LockOwner: pipeline}, ""},
		{"owner deletes", owner, Request{Operation: "DELETE", LockOwner: pipeline}, ""},
		{"owner releases", owner, Request{Operation: "UPDATE", LockOwner: pipeline, Managed: on(false)}, ""},
		{"person updates", person, Request{Operation: "UPDATE", LockOwner: pipeline}, "resource-managed"},
		{"person with full access deletes", person, Request{Operation: "DELETE", LockOwner: pipeline}, "resource-managed"},
		{"other automation updates", stranger, Request{Operation: "UPDATE", LockOwner: pipeline}, "resource-managed"},
		{"other automation releases", stranger, Request{Operation: "UPDATE", LockOwner: pipeline, Managed: on(false)}, "resource-managed"},
		{"containment of a binding", person, Request{ResourceType: "BINDING", Operation: "DELETE", Consent: "ANY", LockOwner: pipeline}, ""},
		{"consent ANY on a source is no containment", person, Request{ResourceType: "SOURCE", Operation: "DELETE", Consent: "ANY", LockOwner: pipeline}, "resource-managed"},
		{"consent ANY update is no containment", person, Request{ResourceType: "BINDING", Operation: "UPDATE", Consent: "ANY", LockOwner: pipeline}, "resource-managed"},
		{"automation creates managed", owner, Request{Operation: "CREATE", Managed: on(true), OwnerJurisdiction: "dc/corp-prod/ledger"}, ""},
		{"person creates managed", person, Request{Operation: "CREATE", Managed: on(true)}, "forbidden"},
		{"operator machine creates managed", machine, Request{Operation: "CREATE", Managed: on(true), OwnerJurisdiction: "dc/corp-prod/ledger"}, "forbidden"},
		{"automation outside its jurisdictions", owner, Request{Operation: "CREATE", Managed: on(true), OwnerJurisdiction: "cloud/fin-01/payments"}, "forbidden"},
		{"binding with one jurisdiction not delegated", owner, Request{ResourceType: "BINDING", Operation: "CREATE", Managed: on(true), SourceJurisdiction: "dc/corp-prod/ledger", TargetJurisdiction: "cloud/fin-01/payments", PlatformJurisdiction: "dc/corp-prod/ledger"}, "forbidden"},
		{"binding with every jurisdiction delegated", owner, Request{ResourceType: "BINDING", Operation: "CREATE", Managed: on(true), SourceJurisdiction: "dc/corp-prod/ledger", TargetJurisdiction: "dc/corp-prod/ledger", PlatformJurisdiction: "dc/corp-prod/ledger"}, ""},
		{"an instance cannot be managed", owner, Request{ResourceType: "PLATFORM", Operation: "CREATE", Managed: on(true), OwnerJurisdiction: "dc/corp-prod/ledger"}, "validation-failed"},
		{"unmanaged create by anyone", person, Request{Operation: "CREATE", Managed: on(false)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := status(Lock(tc.c, &tc.r)); got != tc.want {
				t.Errorf("Lock = %q, want %q", got, tc.want)
			}
		})
	}
}

// FuzzLock: whatever the request, a refusal is always resource-managed or
// forbidden, and a non-owner is never allowed to change a managed resource
// unless it is a containment (the model of §3.2).
func FuzzLock(f *testing.F) {
	f.Add(pipeline, "UPDATE", "BINDING", "ALL", true)
	f.Add(other, "DELETE", "BINDING", "ANY", true)
	f.Fuzz(func(t *testing.T, caller, op, typ, consent string, managedRes bool) {
		r := Request{Operation: op, ResourceType: typ, Consent: consent}
		if managedRes {
			r.LockOwner = pipeline
		}
		err := Lock(spiffeCaller(caller), &r)
		if err != nil {
			if s := status(err); s != "resource-managed" && s != "forbidden" {
				t.Fatalf("unexpected refusal %q", s)
			}
		}
		containment := typ == "BINDING" && op == "DELETE" && consent == "ANY"
		if op != "CREATE" && managedRes && caller != pipeline && !containment && err == nil {
			t.Fatalf("non-owner %q changed a managed resource: %+v", caller, r)
		}
	})
}
