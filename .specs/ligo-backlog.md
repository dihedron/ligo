# ligo: backlog

Work agreed for later, with what is known so far. An item here is not a specification: each needs its own spec, approved, before any code (AGENTS.md rule 1). Update this file when an item is added, started or done.

| No. | Item | Recorded | Status |
| :-- | :------------------------------------ | :--------- | :---------------- |
| 1 | Audit pruning | 2026-11-08 | Not started |
| 2 | Pluggable authentication | 2026-11-08 | Not started |
| 3 | The fix for GO-2026-5932 | 2026-11-08 | Done; move to a tag when one exists |
| 4 | Manual test A-1 | 2026-11-07 | Open: in-person session |
| 5 | Lab work for v0.2.0 | 2026-11-07 | Waiting for the lab host |
| 6 | Product examples in the Planning for Deployment Guide | 2026-11-08 | Later release |
| 7 | Client SDKs (Go, then Python and Java) | 2026-11-08 | Not started |
| 8 | Terraform and OpenTofu provider | 2026-11-08 | Not started; direction set, design open |
| 9 | A map of the `ligo` topology, and a discovery protocol | 2026-11-08 | To explore |
| 10 | Instances managed at run time, plugin types in `server.yaml` | 2026-11-08 | Not started; direction set |
| 11 | An MCP server for the admin API | 2026-11-08 | Not started; tools proposed |

## 1. Audit pruning

**Why.** `audit_log` only grows. Every state change, propagation and workflow outcome adds a row, so on a busy installation the table grows without bound, and with it backups, restores and `audit verify`.

**What makes it hard.** Pruning has to keep the two properties the audit exists for.

- **Append-only (T-13).** The trigger `trg_audit_no_update` in `migrations/001_init_schema.sql` refuses every `UPDATE` and `DELETE`, and `ligo_app` holds only `SELECT` and `INSERT`. A pruning path must not open a way to delete arbitrary rows.
- **The hash chain (§4.3).** Each row's `entry_hash` covers the previous row's hash, starting from 64 zeros. `GET /v1/admin/audit/verify` recomputes from the first row, so deleting the oldest rows breaks verification unless the boundary is kept.

**What is pruned already.** Finished DBOS workflows, after `storage.dbos.workflow_retention` (the sweeper's `retain`, `internal/workflows/sweeper.go`), and delivered or abandoned webhooks after 30 days (`internal/notify/notify.go`). Not pruned: `audit_log`, `change_requests` and retired resources. `001` says retired resources are never deleted, as audit entries and SPIFFE paths refer to them; whether they are in jurisdiction is to decide.

**Direction.**

1. A retention setting, perhaps with no default, so that nothing is deleted unless asked.
2. Archive before delete: export a segment, with the `prev_hash` of its first row and the `entry_hash` of its last, so it can be verified on its own later.
3. An anchor recording the pruned boundary, from which `audit verify` starts.
4. Deletion only through a function owned by the migrator role that deletes below the anchor, in one transaction under the chain's lock, and audits itself; the trigger keeps refusing everything else.
5. Run by a singleton loop (as the sweeper, with `store.TryLock`) or by an operator command: to decide.
6. Tests: verify after pruning, appends during pruning, an archived segment verified alone; pruning under load in the soak. Documentation: a routine procedure, the configuration reference, the threat model.

## 2. Pluggable authentication

**Why.** Organisations want their own sign-in: single sign-on with Kerberos or NTLM (SPNEGO) on the internal network, OpenID Connect elsewhere, and a second factor. Choosing the method should be configuration, not a code change.

**What exists today.**

- People sign in by binding to LDAP (`internal/adminauth`): on the web UI login, and with Basic credentials on the admin API. A successful Basic login is remembered for 10 seconds, so the CLI, which sends Basic credentials on every request, does not cost a directory round trip each time.
- Roles come from LDAP groups (group rules, and for accounts one rule for all of them).
- Web UI sessions live in the database. Group membership is re-checked against LDAP every `authz_recheck_interval` (default 5 minutes, `internal/server/ui/session.go`). If the directory cannot be reached, the request fails and the session is kept: it fails closed.
- Automation signs in with an SVID over mTLS, and is not affected.

**What the design must cover.**

- **Break-glass** demands fresh re-authentication with a password and a live group check (ADR-12 rule 1). With SSO this becomes a step-up at the identity provider: OIDC `max_age` or `acr`, or a second factor.
- **The CLI** needs a flow without a password: the OIDC device flow, or a Kerberos ticket.
- **Where groups come from.** If roles come from identity-provider claims instead of LDAP, the periodic re-check needs a new source, or sessions need a shorter life.
- **Per method:** rate limits, `SESSION_LOGIN_FAILED` auditing, and rows of the threat model (T-36 and the session threats).
- Authorisation stays as it is: roles on jurisdictions. Only where the principal and its groups come from becomes pluggable.

## 3. The fix for GO-2026-5932

**Why.** GO-2026-5932 (the unmaintained `golang.org/x/crypto/openpgp`) was accepted on 2026-10-29, because no fix existed and `ligo` never calls it: `x/crypto` comes in through `go-ldap` (§12, EXT-13).

**What changed.** On 2026-11-08 `govulncheck` names a fix: `golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2`, a pseudo-version, so an untagged commit. The symbol scan still reports that `ligo` is affected by 0 vulnerabilities.

**Decided (2026-11-08).** Bump now, before the soak, so the soak runs on it. `ligo` pins the pseudo-version, `make vuln` reports nothing, and the acceptance note is gone from §12. What remains is to move to the first tagged `x/crypto` release that contains the fix, once there is one.

## 4. Manual test A-1

**Why.** The Accounts web page (chunk 7 of the tenancy work) is covered by tests of its handlers and pages, but nobody has used it in a browser. A-1 in `.specs/ligo-manual-tests.md` is that check. It runs in the in-person session, together with the other manual scenarios.

## 5. Lab work for v0.2.0

**Why.** The release-run of 2026-11-07 passed on OpenBao and on Vault, but four things wait for the lab host, which is busy with another project's stress test.

1. **The release-run of `feature/realm`.** The rename of zone to realm touched the lab scripts; its PR opens only after a release-run passes on the branch.
2. **New lab tests**: group removal ending a role at the session re-check, break-glass through an account group, hostile DNs against a real OpenLDAP, account workloads attested by a real SPIRE agent, and the Setup Guide's accounts example run as written.
3. **The in-person session**, about an hour, before the soak.
4. **The overnight soak**: a generator with a recorded seed, an invariant checker proved against reintroduced bugs, hang and slowness faults, a two-hour shakedown, then one night on Vault (with `-race` and a small pool) and one on OpenBao with all faults. It will use the next lxd-spiffe release (0.3.2 or 0.4.0), bumped before the shakedown.

## 6. Product examples in the Planning for Deployment Guide

**Why.** The guide describes each dependency by its role and names products only as examples. A later release adds worked examples per product, several per role: for example Vault, OpenBao and CyberArk as secret stores, HAProxy and F5 BIG-IP as load balancers.

## 7. Client SDKs (Go, then Python and Java)

**Why.** Today a workload that wants its bindings does several things by hand: it fetches its X.509-SVID from its SPIRE agent, calls `ligo`'s workload API over mTLS (verifying `ligo`'s own SVID), reads the `spec` and `auth` of each binding, fetches a JWT-SVID with the store's audience, logs in to the store and reads its credential, then connects to the target, and does it again when the credential rotates. An SDK would make this one call, such as "give me a connection to target X", wrapping the SPIFFE Workload API.

**What exists.**

- The workload API, over REST (`GET /v1/bindings`, `GET /v1/flows`) and gRPC (`WorkloadBindingService`: `GetBindings`, `GetFlows`, `api/proto/workload/v1alpha1`), with generated Go code in `api/gen/workload/v1alpha1`.
- A working prototype of the whole flow in Go: the lab's `echo-client` (`test/lab/echo/client`, about 240 lines and its tests), which does every step above with `go-spiffe/v2`'s `workloadapi` and `jwtsvid` (`.specs/ligo-echo-target.md`). It is lab code, not hardened.
- `pkg/` today holds only `pluginsdk` and `metadata`: there is no client package.

**To decide.** Go first, in this repository (`pkg/client`) or a module of its own. Then Python and Java, each wrapping that language's SPIFFE library (`py-spiffe`, `java-spiffe`) and generated from the same proto. What the SDK covers beyond discovery: reading credentials per secret storage strategy (`vault-static`, `vault-dynamic`), watching for rotation, checking flows (`/v1/flows`), and how much of the target connection it builds.

## 8. Terraform and OpenTofu provider

**Why.** Teams that manage their infrastructure as code want to declare sources, targets and bindings next to the rest, and have `plan` and `apply` drive `ligo`.

**What exists.** The admin API is described in `api/openapi/admin.v1alpha1.yaml` (48 paths). Every mutation is a change request, with optimistic concurrency (`expectedRevision`) and approval bound to the exact payload (`payloadSha256`). Automation signs in with an SVID, and a `trusted_automation` principal can approve sides of its own jurisdictions by delegation, with a reference to an upstream approval (ADR-11).

**What makes it different from most providers.** An `apply` does not change the resource: it files a change request, which may wait for people of another jurisdiction to approve it. The design must settle:

- what `apply` waits for (the request filed, applied, or the binding `ACTIVE`), with time-outs, and what a later `plan` shows while a request is pending;
- how a pipeline's own review becomes the upstream approval of a `DELEGATED` side, and how that reference is checked;
- drift: what `plan` shows when people changed a resource through the UI;
- read-only data sources for platforms and realms, which live in `server.yaml`, not in the API;
- one provider for Terraform and OpenTofu (the plugin protocol is shared), and its own repository and release.

**Direction set by the user (2026-11-08).**

- The provider creates resources **without waiting for approval**.
- Resources it creates are marked in the database as **managed by automation**. People cannot change them, except by break-glass, and a break-glass change is always reverted: a lasting change goes only through the Terraform manifests again.
- How trustworthy automation bypasses approval is open for discussion. One idea: register in the database, at run time as accounts are, the SVIDs under which **trusted automation workflows** must run, each limited to a subset of jurisdictions.

**Points to discuss, from what `ligo` does today.**

1. **Part of this exists.** ADR-11's `trusted_automation` role already approves sides by delegation for one SPIFFE principal, limited to jurisdictions and platforms, with a reference to an upstream approval. It lives in `server.yaml`. The idea above moves it into the database and adds the managed-by-automation lock.
2. **Bindings across jurisdictions.** Delegation never speaks for the other side, or automation of one jurisdiction could bind into another's targets. Inside the automation's own jurisdictions, no waiting is easy; across them, the other side still consents, unless that rule changes on purpose.
3. **Revocation for containment.** Today any one owner can revoke a binding or lower its level alone (consent `ANY`), so a compromised workload can be cut off at once. If the lock also stops people revoking, containment waits for a manifest change and a pipeline run. Keeping revocation open to people, and flagging the resource as drifted for the pipeline, would avoid that.
4. **Break-glass DELETE.** ADR-12 never reverts an emergency `DELETE`, because restoring it could re-grant access to a compromised workload. "Always reverted" would contradict it. A middle way: the `DELETE` stands, and the next `plan` shows the resource missing and proposes to recreate it, so that a person reviews it before it returns.

## 9. A map of the `ligo` topology, and a discovery protocol

**Why.** With several installations (chapter 5 of the Planning for Deployment Guide), nobody sees the whole picture. A visual map would show, across installations: the realms and federated trust domains of each, who trusts whom, which jurisdictions each one serves, and a few statistics about each one's bindings (counts by phase, failures, expiries).

**What exists.** Each installation knows its own part: realms, federated domains and accepted trust domains in `server.yaml`; platforms and their jurisdictions through the admin API (read-only); bindings by phase and realm as metrics (`ligo_bindings{phase,realm}`). Nothing today connects installations to each other.

**To explore.**

- **Transport.** A request-reply protocol over gRPC, where each installation answers queries about itself, or a gossip membership library such as `hashicorp/serf`, where installations find each other and spread summaries. Gossip fits finding peers; gRPC fits authenticated, audited queries. A mix is possible.
- **Who may see the map.** The topology is sensitive: it tells an attacker where trust is, and who can approve what. Answers go only to a more trusted subset of servers, authenticated by SVID over mTLS, with a dedicated role, and every query is logged.
- **What is shared.** Counts and names, never resources, jurisdictions' members or secrets; whether jurisdiction names themselves may leave an installation is to decide.
- **Where the map is drawn**: the web UI of a designated installation, or a separate read-only tool.

## 10. Instances managed at run time, plugin types in `server.yaml`

**Why.** Identity provider instances, secret store instances and platforms (the instances of platform providers, where targets live) change as often as the systems they describe: a new database, a new Vault namespace. Today each one is an edit of `server.yaml` and a restart. The plugins themselves, and so the types of the three kinds, change rarely, and a new or upgraded binary needs a restart anyway, because its SHA-256 is pinned in `server.yaml` and in SPIRE. The user's direction (2026-11-08): **instances** become manageable through the API and the web UI; **plugin types** stay in `server.yaml`.

**What exists.**

- Platforms, identity provider instances and secret store instances are in `server.yaml`, with their realm, wiring, privilege bounds (`grantable_roles`, `grantable_role_templates`), `allowed_endpoints`, bootstrap credential references and network flows. They are exposed read-only through the API.
- ADR-15 keeps platforms in `server.yaml` on purpose: they carry plugin wiring, bootstrap credentials, privilege bounds and endpoint allowlists, which belong to the platform team's change control (T-22: `server.yaml` root-owned, its SHA-256 logged and audited at startup).
- A binding snapshots its platform's wiring at creation (INV-08), and startup refuses a configuration that removes a platform or instance still referenced by a binding (§8.2 rule 10).
- The plugin manager starts one process per type and realm and sends it `ConfigureInstances` with all that realm's instances at startup (§5.2). Nothing reconfigures a running process today.

**What the design must settle.**

- **Change control instead of file ownership.** If instances move to the database, T-22's protection must move with them: a change request with the platform team as the deciding side (four eyes), audited, with the privilege bounds and endpoint allowlists validated as today. A changed platform keeps the announcement it has today at startup (`CONFIG_PLATFORM_CHANGED`), and bindings outside a tightened bound are still counted (`SYSTEM_PRIVILEGE_BOUND_VIOLATIONS`).
- **Reconfiguring running plugins.** A new or changed instance must reach the running process of its type and realm on every replica, without a restart: `ConfigureInstances` again, or a new RPC to add and remove one instance, and what happens to in-flight calls.
- **Secrets.** Instances reference bootstrap credentials (Vault paths and roles), never hold them; that rule stays, and the API must refuse an instance that embeds a secret.
- **References.** Removing an instance still referenced by a binding is refused, as at startup today; changing an instance's wiring affects only new bindings (INV-08).
- **What stays in `server.yaml`.** Plugin types: binary, SHA-256, kind, and whether they are built in. Realms, probably, since they need SPIRE agents on the hosts.
- **Migration of the configuration.** Instances already in `server.yaml` at upgrade: imported once, or both sources allowed for a while (AGENTS rule 8 prefers no compatibility before a release).

## 11. An MCP server for the admin API

**Why.** People increasingly work through an LLM assistant. An MCP server lets one read `ligo` first ("which bindings does this workload have, and why is this one `FAILED`?"), and later drive it ("request read access to the ledger for my payments project"), through the same admin API and the same rules as the CLI and the web UI.

**What exists.** The admin API (`api/openapi/admin.v1alpha1.yaml`, 48 paths), with authentication by SVID or LDAP, roles on jurisdictions, and visibility that answers `404` for what a caller may not see. The CLI is a client of the same API. The user's `nexus-iq-mcp` project is an MCP server in Go (`mcp-go`) that can serve as a pattern.

**Principles.**

- **The MCP server acts as the person using it**, with their own credentials, never a shared service account: every call is authorised, filtered and audited as theirs, and the LLM can see and do only what that person can.
- **Proposing, never deciding.** The LLM may file change requests on the person's behalf. It never approves, declines, ratifies or reverts a side, and never uses break-glass: maker-checker and the emergency path exist so that a person decides, and an LLM that decides would empty them. Those endpoints are not offered as tools at all.
- **Read first, write later**, as two releases. Every write tool shows the change request it filed and its `payloadSha256`, so the person can review and the approvers decide in the UI or CLI as today.
- **No secrets**: the admin API returns none, and the tools add none (no credentials, no bootstrap references beyond what `getPlatform` shows).

**Proposed tools, phase 1 (read).**

| Tool | API | Answers |
| :---------------------------- | :---------------------------------------- | :---------------------------------------- |
| `search_catalog` | `searchCatalog`, `getCatalogTarget`, `getCatalogTargetFlows` | Which targets exist that I can request, what levels they offer, what flows they need |
| `list_sources`, `get_source` | `listSources`, `getSource`, `listSourceBindings` | My workloads' sources and what they are bound to |
| `test_source_regex` | `testSourceRegex` | Does this regex cover these SPIFFE IDs, and which jurisdiction would it get |
| `list_targets`, `get_target` | `listTargets`, `getTarget`, `listTargetBindings` | My targets, their levels and who uses them |
| `list_bindings`, `get_binding` | `listBindings`, `getBinding`, `getBindingFlows` | Bindings by source, target, phase or expiry; one binding's state, revision and flows |
| `explain_binding` | `getBinding`, `bindingAudit`, `getChangeRequest` | Why a binding is in its phase: its last change requests, decisions and errors, in order |
| `list_change_requests`, `get_change_request` | `listChangeRequests`, `getChangeRequest` | What is pending, what awaits me, who still has to decide |
| `get_audit` | `sourceAudit`, `targetAudit`, `bindingAudit` | The history of one resource |
| `list_platforms`, `get_platform` | `listPlatforms`, `getPlatform` | Platforms, their realms, jurisdictions and health |
| `get_charter`, `check_change` | `getCharter`, `evaluateCharter` | The charter in force; for a planned binding, the jurisdictions, rule, parties and sides, without filing anything |
| `list_accounts` | `listAccounts`, `getAccount` | Registered accounts (for `account_admin` and viewers) |
| `get_maintenance` | `getMaintenance` | Whether changes are accepted now |

**Proposed tools, phase 2 (propose).**

| Tool | API | Does |
| :---------------------------- | :---------------------------------------- | :---------------------------------------- |
| `request_binding` | `evaluateCharter` then `createBinding` | Checks the charter first, then files the request; returns the request and who must decide |
| `change_binding`, `revoke_binding` | `updateBinding`, `deleteBinding` | Files the change; a revocation by an owner applies alone, as today |
| `register_source`, `change_source`, `retire_source` | `createSource`, `updateSource`, `retireSource` | Files the change request |
| `publish_target`, `change_target` | `createTarget`, `updateTarget` | Files the change request |
| `withdraw_change_request` | `withdrawChangeRequest` | Withdraws the person's own pending request |
| `retry_binding`, `rotate_binding` | `retryBinding`, `rotateBinding` | Operational actions the person may already take |

**Never offered.** `approveChangeRequest`, `declineChangeRequest`, `ratifyChangeRequest`, `revertChangeRequest`, `breakGlass`, `putMaintenance`, `recoverExecutor`, `registerAccount`, `retireAccount`, `revokeTargetBindings`.

**To decide.** How the server gets the person's identity (their CLI login or an SVID on their machine, never a stored password); whether it runs locally beside the assistant (stdio) or as a service; prompts or resources that explain jurisdictions and the charter to the model; rate limits; and how a person confirms each write tool before it is sent.

