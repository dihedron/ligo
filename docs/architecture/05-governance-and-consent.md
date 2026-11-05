# Governance and consent

## Either side proposes; each consents

A principal holding `operator` on one of the scopes a change concerns may file it. Who must then consent depends on the change:

| Change | Consent | Sides |
| :--------------------------- | :--- | :---------------------------- |
| Register, narrow, describe or retire a source | All | `OWNER` |
| Publish a target; change its definition or flows; add or narrow a level | All | `OWNER`, `PLATFORM`; one if equal |
| Change a target's metadata; deprecate a level or target | All | `OWNER` |
| Create a binding, raise its level, change its parameters | All | `TARGET`, `SOURCE` if different, `PARTY:<name>` per additional party |
| Revoke a binding, lower its level, bring its expiry forward | Any | One side per scope the requester acts for |

**All** means any one side can veto. **Any** means no other scope can veto: removing privilege is unilateral, so a resource owner can always cut off a compromised client, and a platform owner can contain without the target owner.

![The four topologies, and who consents.](topologies.pdf){width=75%}

## How a side is decided

Fixed at creation:

1. The requester acts for the side, and its scope does not require approval: approved automatically (`AUTO`).
2. The requester is a `trusted_automation` principal covering the side: approved by delegation (`DELEGATED`), with a reference to an upstream approval.
3. Otherwise a person decides (`HUMAN`). An additional party's side is always decided by its approvers.

**The database enforces this.** Sides are rows. Row checks enforce per-side four-eyes and who may decide each basis. Deferred constraint triggers enforce, at commit, the set of sides, completeness before `APPLIED`, the rejection rules, distinct people per side and the delegation reference. A bug in the application, or the `ligo_app` role alone, cannot approve a change.

## Interconnection policy

Two owners agreeing is not always enough: test should not reach production, whoever agrees. Ordered allow and deny rules on pairs of scopes decide, with a default of deny, and can name additional parties, such as Information Security. A denied pair is refused at filing. The policy's hash is stored on every change request, and a change to it is audited and announced.

Bindings that a new policy would deny are not changed: they are logged, audited, announced and counted, for people to decide.

## Delegated approval

Automation can be trusted to decide sides in its own scopes, so that a pipeline with its own review need not ask twice. It never speaks for the other side of a cross-scope binding. It takes a SPIFFE principal, enforced in the database, because a person's account cannot be told from automation.

What SPIFFE can distinguish is the execution context, not the job: two playbooks run by one `python3` under one uid are the same to SPIRE. So run privileged automation on dedicated nodes, and authorize per playbook in the automation platform. `ligo` records the reference, but cannot verify that the approval it names exists.

## Break-glass

The emergency path must be faster than the workaround, or people will use the workaround.

- It takes the `break_glass` role on **every** side that needs a decision: people only, enforced in the database, with fresh re-authentication, a justification and an incident reference.
- It applies at once, and a `CREATE` or `UPDATE` **reverts automatically** at its TTL, unless each side is ratified by another person. So the default outcome is that access disappears again.
- An emergency `DELETE` is never reverted, as restoring it could re-grant access to a compromised workload.

## Visibility

Sources and targets are `PRIVATE` by default. A binding and its requests are visible only to those holding a role on its scopes. For everyone else they do not exist: `404`, so `409` conflicts do not reveal what exists. Name prefixes per scope stop owners squatting on each other's names.
