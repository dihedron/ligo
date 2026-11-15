# Resources and jurisdictions

## Sources

A source's regex is validated on its syntax tree, not as text, to give **segment confinement**: anchored at both ends, with no `.`, no character class that includes `/`, no `/` inside a repeated or optional group, and no alternation at the top. Matching uses RE2, in linear time, so a regex cannot be a denial of service.

A source's owner jurisdiction is derived from the fixed literal beginning of its regex, by the extractor configured for its trust domain. A regex whose beginning does not identify exactly one jurisdiction is refused. So nobody chooses a source's jurisdiction: the SPIFFE path does.

A source can only **narrow**. `ligo` proves with a bounded automaton check that the new regex accepts a subset of the old; undecided counts as not narrowing. Otherwise an in-place edit could add workloads to bindings already approved.

## Targets and access levels

A target's jurisdiction is chosen at publication, among those the platform allows. Its access levels name privileges within the platform's bounds, and `ligo` knows them canonically, so it can tell exactly whether one level is contained in another. Whether a change only removes access decides who must approve it, so this is never estimated.

## Platforms and instances

A platform, an identity provider instance and a secret store instance are resources too: each has a jurisdiction, revisions and an audit history, and changes only through a change request that a second person of that jurisdiction decides; no side of it is ever decided automatically, by delegation or by break-glass. Its name, type, realm and jurisdiction never change. Only plugin types stay in `server.yaml`, with `instance_bounds`, the root-owned limit on where their instances connect.

Every replica keeps the instances in force in memory, reloaded on each change, and verifies each row's signature by the audit key: a row edited outside `ligo` is quarantined. The plugin manager reconciles its processes with that set, so a new platform is usable without a restart. A platform's change affects new bindings only: a binding keeps the wiring it was created with.

## Bindings

A binding has three jurisdictions, copied from what it links: source, target and platform. None changes, except through an audited transfer at startup. A binding snapshots its wiring at creation, so a later configuration change affects only new bindings.

A principal's name is derived from the binding's UUID, in 20 characters, so two bindings cannot collide. Resources are tagged `ligo:binding_id=<uuid>`. Finding a resource tagged otherwise fails `Ensure`, and is skipped by `Cleanup`.

## Managed resources

A source, target or binding filed with `managed: true` by a `trusted_automation` principal carries `managed_by`, that principal's SPIFFE ID. The principal needs the role on every jurisdiction the resource involves: the owner, and for a binding its source, its target and the platform. The column is set by the change request that applies, and a database trigger refuses any other update of it. Instances, platforms and accounts have no such column.

A change to a managed resource by anyone else is refused at filing (`409 resource-managed`, nothing stored) and again in the applying transaction, under the row lock, so a change filed before a lock was set does not apply after it. Revoking a binding that people removed in an emergency leaves a row in `managed_holds`, and the owner's creation of the same name is refused (`409 resource-held`) until a person who approves a side lifts it. The lock changes who may edit a resource, not what it may reach: the charter, the consent of the sides and the platform's bounds apply as before.

## Network flows

A target and a platform declare the flows needed to reach them, within `allowed_endpoints`. Workloads read their effective flows from `GET /v1/flows`, so a verification tool on the host can check them, before any traffic depends on them.

## Change requests

Every mutation of a source, target or binding is a change request. It is bound to the exact payload by its SHA-256, which an approver must present, and to the charter by its hash. A change that would be applied differently than approved is refused with `normalization-drift` or `charter-changed`.
