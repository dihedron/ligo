# Resources and scopes

## Sources

A source's regex is validated on its syntax tree, not as text, to give **segment confinement**: anchored at both ends, with no `.`, no character class that includes `/`, no `/` inside a repeated or optional group, and no alternation at the top. Matching uses RE2, in linear time, so a regex cannot be a denial of service.

A source's owner scope is derived from the fixed literal beginning of its regex, by the extractor configured for its trust domain. A regex whose beginning does not identify exactly one scope is refused. So nobody chooses a source's scope: the SPIFFE path does.

A source can only **narrow**. `ligo` proves with a bounded automaton check that the new regex accepts a subset of the old; undecided counts as not narrowing. Otherwise an in-place edit could add workloads to bindings already approved.

## Targets and access levels

A target's scope is chosen at publication, among those the platform allows. Its access levels name privileges within the platform's bounds, and `ligo` knows them canonically, so it can tell exactly whether one level is contained in another. Whether a change only removes access decides who must approve it, so this is never estimated.

## Bindings

A binding has three scopes, copied from what it links: source, target and platform. None changes, except through an audited re-scoping at startup. A binding snapshots its wiring at creation, so a later configuration change affects only new bindings.

A principal's name is derived from the binding's UUID, in 20 characters, so two bindings cannot collide. Resources are tagged `ligo:binding_id=<uuid>`. Finding a resource tagged otherwise fails `Ensure`, and is skipped by `Cleanup`.

## Network flows

A target and a platform declare the flows needed to reach them, within `allowed_endpoints`. Workloads read their effective flows from `GET /v1/flows`, so a verification tool on the host can check them, before any traffic depends on them.

## Change requests

Every mutation of a source, target or binding is a change request. It is bound to the exact payload by its SHA-256, which an approver must present, and to the governance policy by its hash. A change that would be applied differently than approved is refused with `normalization-drift` or `governance-policy-changed`.
