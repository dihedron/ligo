# Resources managed by automation (the lock)

- **Version:** 0.2 (2026-11-15), approved by the user on 2026-11-15 with the five recommended decisions of §8; implementation starts with chunk 1 (AGENTS.md rules 1 and 3).
- **Backlog:** item 16 (this one); it unblocks the resources of item 8, the Terraform and OpenTofu provider (`terraform-provider-ligo/.specs/ligo-terraform-provider.md` §3.7, chunk 4)
- **Builds on:** ADR-09 (maker-checker), ADR-11 (delegated approval for `trusted_automation`), ADR-12 (break-glass), ADR-13 (jurisdictions and two-sided consent), `.specs/ligo-adminclient.md`
- **Direction of the user (2026-11-08, restated 2026-11-15):** a resource that automation creates is marked "managed by automation"; people cannot change it, except a binding through break-glass, and break-glass changes are always reverted; a lasting change goes only through the automation's own source of truth (the Terraform configuration) again.

## 1. Why

ADR-11 already lets a `trusted_automation` principal apply changes without a human approver, inside its jurisdictions, with an upstream `approvalReference`. That makes infrastructure as code workable, and it creates a second problem: the pipeline's configuration is the declared truth, and a person who edits the same resource in the UI or with the CLI makes the truth and the system disagree. The next `terraform apply` silently overwrites the person's change, or the person's change silently outlives the review that the pipeline went through. The lock makes the ownership explicit and enforced: a managed resource has one owner, the automation that filed it, and the server refuses the others.

This is not a new way to skip approval. Delegation (ADR-11) stays what it is. The lock only narrows who may change a resource after it exists.

## 2. Scope

In: sources, targets and bindings created by a `trusted_automation` principal; the rules for who may change, release, contain and break-glass a managed resource; the data model, the admin API, `pkg/adminclient`, the CLI and the UI's badge; audit, webhooks and metrics; tests; documentation.

Out: platforms, identity providers and secret stores (instances are never delegated and always wait for a person, `.specs/ligo-instances.md` T-22: there is nothing for an automation to own); accounts; a lock on the charter or on `instance_bounds` (they are not in the database); a lock for LDAP users (a person is not automation, ADR-11); locking for any other purpose.

## 3. Design

### 3.1 Who owns a lock

A managed resource has an **owner**, the exact SPIFFE ID of the principal that filed its creation. Only a principal that holds `trusted_automation` on the resource's jurisdiction can create a managed resource, by saying so in the request (`managed: true`); a request from anyone else with `managed: true` is `403 forbidden`. The SPIFFE ID is the identity: two pipelines that run as the same ID are one owner, which is how a pipeline's successive runs and a team's several runners share what they manage. Two different IDs are two owners and cannot touch each other's resources.

Alternative considered and not recommended: a run-time registry of automations in the database (the user's 2026-11-08 idea, like accounts), with its own SVIDs and jurisdiction subsets, instead of `server.yaml` `authorization.bindings`. It would give administrators a way to add and retire automations without a restart. It is a larger change (a second authorization model beside ADR-11's) and is not needed for the lock; if it is built later, the owner becomes a name in the registry and the rules below do not change. Decision 1 in §8.

### 3.2 What the lock refuses

On a managed resource the server accepts a change only from its owner. For everyone else, including a principal with `operator`, `approver` or `trusted_automation` on the same jurisdiction, and including a person with `admin.full_access`:

| Operation | Result |
|---|---|
| read, list, audit | allowed; the resource shows `managedBy` |
| update, state change (deprecate, reactivate, retire), delete, bulk revocation by name | `409 resource-managed`, nothing is filed |
| break-glass on a managed binding | allowed to people who hold `break_glass` on every side (ADR-12), under §3.5 |
| containment: a revocation (consent `ANY`) by the owner of the source, the target or the platform of a binding | allowed (§3.4) |
| release (`managed: false`) | only the owner, or by the procedure of §3.3 |

The refusal is made where the change request is created, before any side is decided, so that nothing sits pending that could not be approved. It is also checked again when the change is applied, in the same transaction as the apply, so that a lock set between filing and applying is honoured (the same pattern as `payloadSha256` and revision checks).

### 3.3 Release, adoption and orphans

- **Release by the owner:** the owner files an update with `managed: false`. It is a change like any other (delegated inside the owner's jurisdictions); after it, the resource is an ordinary one that people may edit.
- **Adoption:** a person's resource is not made managed by the owner silently. The owner files an update with `managed: true` against its current revision; because the resource was not managed, any principal that may change it may also hand it over, so the update needs the sides that a change of that resource needs (a source: its `OWNER` side; a target: `OWNER` and `PLATFORM`; a binding: its sides). The resource's existing owners therefore agree to the handover, and an automation cannot take over what it cannot already change.
- **Orphans:** when an automation is retired or its SVID is no longer accepted, nobody can release its resources. A person with `admin.full_access` files a **release by administrator** (`POST /v1/admin/{type}/{name}/release`, with a justification of at least `min_justification_length` characters), a four-eyes request with consent `ALL` on the resource's own sides, decided by people only (never `DELEGATED`, never `AUTO`). It is audited with the original owner. This is the only way anyone but the owner takes a lock off.
- **Two owners:** an update by a principal that is not the owner never succeeds; there is no race between two automations over one resource.

### 3.4 Cross-jurisdiction and containment

- **The lock never speaks for the other side (ADR-13).** An owner's delegation covers only the sides within its own jurisdictions. A managed binding between two jurisdictions still needs the other owner's consent to be created or raised, exactly as for any binding; the lock only restricts what happens afterwards.
- **Containment is never blocked.** ADR-13 rule 5 lets the platform owner, and either side's owner, revoke a binding unilaterally (consent `ANY`), for incident response. The lock does not stop it, or incident response would depend on the automation being reachable. A revocation by someone other than the owner is filed and decided as before; when it applies, the binding is deleted and a **hold** is recorded (§3.5).
- **Bulk revocation (`revokeTargetBindings`)** works on managed bindings by the same rule.

### 3.5 Break-glass and holds

The user's rule, "break-glass is always reverted", and ADR-12 rule 4, "an emergency delete is never reverted" (restoring access could re-grant it to a compromised workload), are reconciled like this:

- **A break-glass `CREATE` or `UPDATE` of a managed binding can never be ratified.** Ratification is how ADR-12 makes an emergency change last; for a managed binding, a lasting change goes through the owner (the Terraform configuration), so ratification is refused with `409 resource-managed` and the change is **always reverted** when its TTL ends (as an unratified one is today). A break-glass `CREATE` of a binding whose name is managed by an owner is refused: the name belongs to the owner; the person breaks glass on a name of their own.
- **A break-glass `DELETE`, and a containment revocation, stay final** (ADR-12 rule 4). They leave a **hold** on the binding's name: a row that records the deleted binding's source, target and level, who deleted it and when. While the hold stands, the owner's attempt to create the same binding again is refused with `409 resource-held` and the hold's reference, so that the pipeline does not re-grant, at its next run, the access that a person removed in an emergency. The hold ends when a person who may approve a side of the binding lifts it (`POST /v1/admin/holds/{id}/lift`, with a comment), which is an audited, four-eyes-neutral act (it only restores the owner's right to ask; the re-creation is still filed, and still needs the other sides' consent where ADR-13 asks for it). A hold also ends when the revocation's review is ratified, if it was a break-glass one, and never by the passing of time.
- **Sources and targets are not break-glassed** (ADR-12): nobody changes a managed source or target but its owner. Containment on them is the retirement of the bindings that use them.

### 3.6 Data model

- `sources`, `targets`, `bindings`: a column `managed_by VARCHAR(255) NULL` (the owner's SPIFFE ID), immutable except through a change request that sets or clears it (a database trigger refuses any other update of it); a `CHECK` that `managed_by LIKE 'spiffe://%'`; an index on it.
- `managed_holds(id, resource_name, source, target, access_level, deleted_by, deleted_at, basis, change_request_id, lifted_by, lifted_at)`, with a unique partial index on the open ones per `(source, target, access_level)`.
- `change_requests`: the lock's owner at filing, so that the application of the change can check it again.
- A change request that sets `managed: true` must have `requested_by LIKE 'spiffe://%'` and a `DELEGATED` basis on the owner's sides (database `CHECK`, like `chk_side_basis`).
- A migration with no compatibility shim (AGENTS.md rule 8): existing resources are unmanaged.

### 3.7 Admin API, client, CLI and UI

- The OpenAPI document gains `managedBy` (string, null) on sources, targets and bindings, `managed` (boolean) on the create and update bodies (an `Options` field of the client, `Options.Managed`), `release` and `holds` operations, and the problems `resource-managed` and `resource-held` (both mapped by `pkg/adminclient` to `ErrState`, with a test that the slug list is complete, as `TestSlugsAreMapped` already requires).
- `pkg/adminclient`: `Options.Managed`, the `ManagedBy` field of the types, `ReleaseResource`, `ListHolds`, `LiftHold` (a person's act, so not for the provider: it joins the methods that a tool's tests keep out, like the decisions).
- The CLI: `--managed` on `ligo apply` for automation users; `ligo hold list|lift`; `ligo <type> release`.
- The UI: a "managed by `<owner>`" badge on a managed resource and the reason that edit buttons are off; a banner for a hold on the binding's page.

### 3.8 Audit, webhooks and metrics

Audit actions: `RESOURCE_MANAGED` (the filing that sets it), `RESOURCE_RELEASED` (by the owner), `RESOURCE_RELEASED_BY_ADMIN`, `LOCK_VIOLATION_REFUSED` (who tried, what, which owner; rate-limited in the log like other refusals so it cannot flood it), `HOLD_CREATED`, `HOLD_LIFTED`. Each is also a webhook event and a SIEM line (§7.5). Metrics: `ligo_lock_violations_total{type}`, `ligo_managed_resources{type}`, `ligo_holds_open`.

### 3.9 Interplay

- **Pruning:** audit and change request pruning keep what the holds and the locks name (a hold's change request and the audit entries that created and lifted it are not pruned while the hold is open).
- **Blueprints and the transfer procedure (§8.2 rule 17):** a transfer of a managed resource to another jurisdiction is refused (`409 resource-managed`) unless it is released first.
- **Accounts:** retiring an account refuses while it has active managed resources, as it does for active resources.
- **Delegated approval's rate limit** (ADR-11 rule 5) is unchanged and applies to the owner.

## 4. Threat model

| # | Threat | Mitigation |
|---|---|---|
| T-M1 | A person or another automation changes a managed resource through any write path, bypassing the lock. | The check is made where the change request is created and again in the transaction that applies it; it covers every write that reaches a source, a target or a binding (create, update, state change, delete, bulk revocation, retry and rotate are not changes of the resource but are tested, break-glass, transfer, blueprints); a table-driven test runs every operation of the OpenAPI document against a managed resource as a non-owner, so a new operation without a lock decision fails the build. |
| T-M2 | Lock squatting: a hostile or compromised automation locks resources it can reach so that their owners cannot change them. | Only `trusted_automation` can lock, only within its own jurisdictions and platforms; adoption needs the resource's existing sides to agree (§3.3); the administrator's release exists and is audited; containment is never blocked. The blast radius is the one that ADR-11 already accepts (T-25). |
| T-M3 | A compromised owner SVID uses the lock to hide its changes. | Every change is audited with `approvalReference` and `automationContext` as before; locks add `RESOURCE_MANAGED` and the refusal log; the SVID's registration advice (§10.6) is unchanged. A lock cannot block containment. |
| T-M4 | An orphaned lock: the automation is gone and nobody can change the resource. | The release by administrator (§3.3): four-eyes, people only, with a justification, audited. |
| T-M5 | The lock blocks incident response. | Containment (ADR-13 rule 5) and break-glass (ADR-12) are not blocked; a test proves that the platform owner can revoke a managed binding and that a break-glass holder can change one. |
| T-M6 | The pipeline re-grants access that a person removed in an emergency. | The hold (§3.5): the owner's re-creation is refused until a person lifts it. |
| T-M7 | A break-glass change on a managed binding becomes permanent by ratification. | Ratification is refused for a managed binding; the change is reverted at its TTL like any unratified one. |
| T-M8 | A race between a lock being set and a change being applied. | The check in the applying transaction, under the same row lock the binding's other concurrency rules use (ADR-12 ratify/revert); a concurrency test. |
| T-M9 | The refusals flood the audit log. | `LOCK_VIOLATION_REFUSED` is audited with a per-principal, per-resource rate limit and counted in a metric. |
| T-M10 | The owner column is changed outside a change request, in the database. | A trigger refuses any update of `managed_by` that is not part of an applying change request; a test with the application's role, as for the other immutable fields. |

## 5. Tests first

| # | Criterion | Test |
|---|---|---|
| AC-M1 | A `trusted_automation` principal creates a managed source, target and binding; anyone else's `managed: true` is `403`. | HTTP tests against the admin handler; service tests. |
| AC-M2 | A non-owner, whatever its roles, cannot update, change the state of, delete or bulk-revoke a managed resource (`409 resource-managed`), and nothing is filed. | The table-driven test over every operation of the OpenAPI document (T-M1). |
| AC-M3 | The owner changes, releases and deletes its own resources; after a release a person may edit the resource. | Service tests. |
| AC-M4 | Adoption needs the existing sides; the administrator's release is four-eyes and people only. | Service tests, with distinct approvers. |
| AC-M5 | Containment: the platform owner, and either side's owner, can revoke a managed binding; a hold is created. | Integration test. |
| AC-M6 | Break-glass on a managed binding: allowed, never ratifiable, always reverted at the TTL; a break-glass create on a managed name is refused. | Integration test with a fast TTL, as the break-glass suite does. |
| AC-M7 | A hold refuses the owner's re-creation; a person's lifting ends it; time does not. | Integration test. |
| AC-M8 | A lock set between filing and applying is honoured; two owners cannot race. | Concurrency test. |
| AC-M9 | The database refuses a change of `managed_by` outside a change request, and a managed change by a non-SPIFFE requester. | Integration tests with the application's role. |
| AC-M10 | The contract: `managedBy`, `managed`, the problems and the new operations are in the OpenAPI document and the client; every new slug is mapped. | `TestOpenAPI*`, `TestSlugsAreMapped`, `make generate-check`. |
| AC-M11 | The lab: a managed binding applied by an automation SVID, refused to a person, contained by the platform owner, held, lifted, and the audit chain verifies. | A lab suite, `lab.sh serve test-managed`, run by `release-run` on both backends. |

Proposed, for the user to accept: a fuzz target for the lock decision (random sequences of operations by random principals against a managed resource, checked against a model), and a chaos step in the lab that kills a replica between filing and applying a lock.

## 6. Documentation

Main specification: a new ADR-17 and the threats T-M1 to T-M10 in its register; the admin API chapter; the changelog. Guides: the Operator's Guide (what a lock is, who may release, the hold and how to lift it, the orphan procedure), the Architecture and Design Guide (the rules and the threat model), the Setup Guide (nothing to configure; the upgrade note says that nothing is locked after the migration), the Developer's Guide (Part 3: `Options.Managed` and what a tool sees). The README's status lists it.

## 7. Chunks

| Chunk | Content |
|---|---|
| 0 | This spec, approved. |
| 1 | The tests of AC-M1 to AC-M3 and AC-M9, then the migration and the service rules for sources, targets and bindings. |
| 2 | Containment, break-glass and holds (AC-M5 to AC-M8). |
| 3 | The OpenAPI document, `pkg/adminclient`, the CLI (AC-M10). |
| 4 | The UI badge, the audit, webhook and metric events. |
| 5 | The lab suite and the release run (AC-M11); the documentation. |

Each chunk is committed only on the user's word, after `go test ./...`, `make lint`, `make vuln` and `make secrets`.

## 8. Decisions (all taken 2026-11-15)

The user chose the recommended option of each.

1. **The owner's identity:** the SPIFFE ID of the principal that filed the creation (recommended, §3.1), or a run-time registry of automations (the user's 2026-11-08 idea; a larger change, and not needed for the lock).
2. **Holds:** the owner's re-creation is refused after a person's emergency deletion or containment until a person lifts the hold (§3.5, recommended), or the pipeline re-grants at its next run and the hold is only an alert.
3. **Ratification of a break-glass change on a managed binding is refused** (§3.5, recommended; it is how "always reverted" holds), or allowed, in which case the change becomes a normal change of an unmanaged resource that the owner overwrites at its next run.
4. **Adoption** of an existing resource by an automation needs the existing sides to agree (§3.3, recommended), or the automation's delegation alone suffices (it would let an automation take over what people made and lock them out).
5. **Release by an administrator** is a four-eyes request by people (§3.3, recommended), or one act by `admin.full_access`.
