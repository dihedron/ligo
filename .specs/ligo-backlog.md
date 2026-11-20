# ligo: backlog

Work agreed for later, with what is known so far. An item here is not a specification: each needs its own spec, approved, before any code (AGENTS.md rule 1). Update this file when an item is added, started or done.

Until 1.0.0, a release does not wait for open items: each one that affects users is listed as a known limit in the README's Status section, with its number here.

| No. | Item | Recorded | Status |
| :-- | :------------------------------------ | :--------- | :---------------- |
| 1 | Audit pruning | 2026-11-08 | Done in v0.3.0 (PR #42) |
| 2 | Pluggable authentication | 2026-11-08 | Not started |
| 3 | The fix for GO-2026-5932 | 2026-11-08 | Done: `x/crypto` v0.59.0, the first tag without `openpgp`, in v0.3.0 |
| 4 | Manual test A-1 | 2026-11-07 | Postponed past v0.2.0; known limit |
| 5 | Lab work for v0.2.0 | 2026-11-07 | Soak done; new lab tests and in-person session postponed past v0.2.0 |
| 6 | Product examples in the Planning for Deployment Guide | 2026-11-08 | Later release |
| 7 | Client SDKs (Go, then Java, Python and JavaScript/TypeScript) | 2026-11-08 | Go released in v0.5.0 (2026-11-14): `.specs/ligo-client-sdk.md`; Python in progress on `feature/python-sdk` (`.specs/ligo-client-sdk-python.md`; items 20 to 24 are what it leaves out); Java released in v0.11.0 (2026-11-20; `.specs/ligo-client-sdk-java.md`, lab-tested on REST and gRPC); JavaScript/TypeScript not started |
| 8 | Terraform and OpenTofu provider | 2026-11-08 | Released as v0.1.0 on GitHub (2026-11-17), on `ligo` v0.7.0 and the Go admin client; resources and data sources done, pre-release campaign passed. Left: the soak before v0.2.0 and the registries, in the provider's own backlog (`terraform-provider-ligo/.specs/ligo-provider-backlog.md`) |
| 9 | A map of the `ligo` topology, and a discovery protocol | 2026-11-08 | To explore |
| 10 | Instances managed at run time, plugin types in `server.yaml` | 2026-11-08 | Done in v0.4.0 (PR #45): `.specs/ligo-instances.md` |
| 11 | An MCP server for the admin API | 2026-11-08 | Not started; tools proposed; needs the Go admin client, `.specs/ligo-adminclient.md` (approved; built on `feature/adminclient`, chunks 0 to 6 done 2026-11-14, PR pending) |
| 12 | Network checks in the client SDK, from netcheck | 2026-11-09 | Done in v0.8.0 (PRs #60, #62), and its lab scenario (chunk 3) with the PostgreSQL and SPIFFE handshakes, on netcheck v2.1.0, in v0.9.0 (PR #64): `.specs/ligo-network-checks.md` |
| 13 | Outbox retention: delivered events kept 30 days | 2026-11-09 | Done in v0.3.0 (PR #42): `notifications.delivered_retention`, `abandoned_retention` |
| 14 | Post-quantum signatures for audit checkpoints | 2026-11-10 | Waiting for OpenBao or Vault Community |
| 15 | Change request pruning | 2026-11-11 | Done in v0.3.0 (PR #43) |
| 16 | Resources managed by automation (the lock) | 2026-11-15 | Done in v0.7.0 (PRs #53 and after): `.specs/ligo-managed-resources.md` |
| 17 | Man pages and shell completions for `ligo` | 2026-11-18 | Done in v0.8.0 (PR #61): `.specs/ligo-cli-extras.md` (netcheck's: v2.0.0) |
| 18 | A hint in a flow for the kind of TLS handshake (`postgresql`, `spiffe`), so that a client no longer maps flows to checks itself | 2026-11-19 | Not started; see §18 |
| 19 | `flowcheck` left out of v0.8.0: a command line, a check on the first fetch, CIDRs and ranges, DTLS, SSH and HTTP flows | 2026-11-19 | Not started; see §19 |
| 20 | A Python asyncio client | 2026-11-19 | Not started; see §20 |
| 21 | ICMP in the Python SDK's flow testing | 2026-11-19 | Not started; see §20 |
| 22 | Publish `ligo-client` on PyPI and the Java SDK on Maven Central | 2026-11-19, Maven Central 2026-11-20 | Waiting for a stable ecosystem, like the Terraform provider's registries; all go out together; see §20 |
| 23 | A gRPC transport in the Python SDK | 2026-11-19 | Blocked: `grpcio` cannot verify the server's SPIFFE ID; see §20 |
| 24 | Connection reuse in the Python SDK, and signing or attesting the wheel | 2026-11-19 | Not started; see §20 |
| 25 | A description and an annotations map (first asked for as "metadata") on each binding, sent to the client | 2026-11-19 | Done in v0.10.0 (migration 002): `.specs/ligo-binding-annotations.md`; see §25 |
| 26 | MIT license for the client libraries and SDKs (`pkg/client`, `pkg/adminclient`, `sdk/*`), the server staying AGPL-3.0 | 2026-11-19 | Done (2026-11-19): MIT; see §26 |
| 27 | An admin API client in Python (first, for Ansible), later in Java | 2026-11-20 | Not started; see §27 |
| 28 | An Ansible collection: install and set up ligo, manage the server, manage sources, targets and bindings | 2026-11-20 | Not started; needs item 27; see §28 |
| 29 | Flow-check semantics in netcheck, with pure-Python and pure-Java ports sharing conformance vectors | 2026-11-20 | Not started; see §29 |
| 30 | `annotations` on sources and targets (the rename of `labels`), v0.12.0, then the Terraform provider's three resources | 2026-11-20 | Done in v0.12.0 (migration 003, PR #71; `.specs/ligo-resource-annotations.md`); the provider follows in v0.2.0 |

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

**Decided (2026-11-08).** Bump now, before the soak, so the soak runs on it. `ligo` pins the pseudo-version, `make vuln` reports nothing, and the acceptance note is gone from §12. On 2026-11-12 `ligo` moved to `x/crypto` v0.59.0 (tagged 2026-11-11), the first release without `openpgp`: the item is closed.

## 4. Manual test A-1

**Why.** The Accounts web page (chunk 7 of the tenancy work) is covered by tests of its handlers and pages, but nobody has used it in a browser. A-1 in `.specs/ligo-manual-tests.md` is that check. It runs in the in-person session, together with the other manual scenarios.

## 5. Lab work for v0.2.0

**Why.** The release-run of 2026-11-07 passed on OpenBao and on Vault, but four things wait for the lab host, which is busy with another project's stress test.

1. **The release-run of `feature/realm`.** The rename of zone to realm touched the lab scripts; its PR opens only after a release-run passes on the branch.
2. **New lab tests**: group removal ending a role at the session re-check, break-glass through an account group, hostile DNs against a real OpenLDAP, account workloads attested by a real SPIRE agent, and the Setup Guide's accounts example run as written.
3. **The in-person session**, about an hour, before the soak.
4. **The overnight soak**: a generator with a recorded seed, an invariant checker proved against reintroduced bugs, hang and slowness faults, a two-hour shakedown, then one night on Vault (with `-race` and a small pool) and one on OpenBao with all faults. It will use the next lxd-spiffe release (0.3.2 or 0.4.0), bumped before the shakedown.

**Status (2026-11-11).**
- Item 1, the release-run of `feature/realm`, passed, and the branch was merged (PR #31).
- Item 4, the soak, is done. Night 2 (9 h, OpenBao, every fault and pairs of faults) had 0 violations. The backup and restore drill and the audit tamper drill passed after it. The code is merged in PRs #36, #37 and #38.
- Items 2 and 3, the new lab tests and the in-person session, are postponed past v0.2.0. The README lists both as known limits.

## 6. Product examples in the Planning for Deployment Guide

**Why.** The guide describes each dependency by its role and names products only as examples. A later release adds worked examples per product, several per role: for example Vault, OpenBao and CyberArk as secret stores, HAProxy and F5 BIG-IP as load balancers.

## 7. Client SDKs (Go, then Python and Java)

**Why.** Today a workload that wants its bindings does several things by hand: it fetches its X.509-SVID from its SPIRE agent, calls `ligo`'s workload API over mTLS (verifying `ligo`'s own SVID), reads the `spec` and `auth` of each binding, fetches a JWT-SVID with the store's audience, logs in to the store and reads its credential, then connects to the target, and does it again when the credential rotates. An SDK would make this one call, such as "give me a connection to target X", wrapping the SPIFFE Workload API.

**What exists.**

- The workload API, over REST (`GET /v1/bindings`, `GET /v1/flows`) and gRPC (`WorkloadBindingService`: `GetBindings`, `GetFlows`, `api/proto/workload/v1alpha1`), with generated Go code in `api/gen/workload/v1alpha1`.
- A working prototype of the whole flow in Go: the lab's `echo-client` (`test/lab/echo/client`, about 240 lines and its tests), which does every step above with `go-spiffe/v2`'s `workloadapi` and `jwtsvid` (`.specs/ligo-echo-target.md`). It is lab code, not hardened.
- `pkg/` today holds only `pluginsdk` and `metadata`: there is no client package.

**To decide.** Go first, in this repository (`pkg/client`) or a module of its own. Then Python and Java, each wrapping that language's SPIFFE library (`py-spiffe`, `java-spiffe`) and generated from the same proto. What the SDK covers beyond discovery: reading credentials per secret storage strategy (`vault-static`, `vault-dynamic`), watching for rotation, checking flows (`/v1/flows`), and how much of the target connection it builds.

**Status (2026-11-14).** The Go SDK is done, in `feature/client-sdk` (PR pending; also its Developer's Guide, the configurable dynamic lease and Vault namespaces in bindings). It was started 2026-11-13 and is specified in `.specs/ligo-client-sdk.md`: `pkg/client` in this module; bindings, credentials (`vault-static`, `vault-dynamic`), a watch for changes and rotation, flows as data; REST and gRPC, selectable. The target connection stays with the application. A new release PDF, the Developer's Guide, covers the client SDK and, in a second part, writing plugins. Java, Python and JavaScript/TypeScript follow, each with its own spec.

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

**Status (2026-11-12).** Done in v0.4.0 (PR #45, released 2026-11-12). Decided and specified in `.specs/ligo-instances.md`, with `instance_bounds.shared_svids` added in the lab work: all three kinds, four-eyes change requests per jurisdiction, no migration (instances by `ligo apply`), `ca_pem` instead of `ca_file`. The points below are settled there.

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

## 12. Network checks in the client SDK, from netcheck

**Why.** Each binding carries its network flows: the target's, the platform's, the secret store's and ligo's own (`GET /v1/flows`, AC-73). Today a workload learns that a flow is blocked only when its first connection fails. If the client SDK (item 7) could check those flows itself, a workload or an operator could see at once which flow a firewall still blocks, before the application tries.

**What exists.** The user wrote [netcheck](https://github.com/dihedron/netcheck) independently, as a standalone command. It runs bundles of checks, written in JSON or YAML, with timeouts, retries and concurrency, over TCP, UDP, ICMP, SSH, HTTP and HTTPS, TLS and DTLS, with certificate verification. Its checking code lives in the package `checks` (bundle, check, defaults), about 1,000 lines with the command around it, and four test files.

**The steps, in order.**
1. **Review netcheck** against the quality standards of ligo and lxd-spiffe: tests, linting, `govulncheck`, secret scanning, CI, docs.
2. **Refactor the checking code into a library**, with an API that does not depend on the command, its output or its configuration files; the command then becomes one user of it.
3. **Depend on it from the client SDK.** The SDK turns a binding's flows (destination, ports, protocol, `tls`, `serverName`) into checks and runs them on the client, reporting each flow as reachable or not.

**To decide.**
- Which of netcheck's protocols the flows need: the flows declare TCP and UDP, with or without TLS. ICMP, SSH and HTTP may stay in the command.
- Whether a flow with `tls: true` is checked up to the TLS handshake, and against which roots: the workload's trust bundle, or the system's.
- Where the library lives: in netcheck's repository, as its own module, or moved under ligo.
- Whether the check runs only on demand, or also when the SDK first fetches a binding.

## 13. Outbox retention: delivered events kept 30 days

**Why.** The soak's 2-hour baseline of 2026-11-09 grew `notification_outbox` from 797 to 3,786 rows, while ligo itself did not drift. The table holds every webhook event ever queued: the dispatcher marks a row delivered or abandoned and deletes it only 30 days later (`internal/notify/notify.go`, the main spec's notification dispatcher: "purge delivered or abandoned rows after 30 days"). On a busy installation, that is 30 days of every event's payload. The user's view: once a webhook has been invoked, its row should go, and in any case it should go after some time.

**What exists.** The 30-day purge runs on every dispatcher pass, as one `DELETE` on `coalesce(delivered_at, abandoned_at)`. The period is a constant, not a setting.

**Options.**
- Delete a row as soon as its webhook answers 2xx. The table then holds only what is still pending.
- Keep delivered rows for a short, configurable window: it shows what was sent and when, if a receiver says it never got an event. Whether the audit log already records enough of that decides how much this is worth.
- Keep abandoned rows longer than delivered ones: they are the ones somebody must investigate.

**Affects.**
- The soak's SK-9 check (`.specs/ligo-soak.md`), which compares the delivered rows with what the receiver logged. Deleted at once, the rows would no longer be there to compare.
- The webhook e2e in `lab.sh serve test-webhook`, which reads delivered rows.

## 14. Post-quantum signatures for audit checkpoints

**Why.** Audit checkpoints (spec §4.3) are signed with the Transit key `ligo-audit`, of type `ed25519`. A quantum computer able to break ed25519 could forge checkpoints, and with them a rewritten chain. Signatures are not exposed to "harvest now, decrypt later": the attacker needs that computer when they rewrite the log. The risk grows with retention: a log kept ten years or more could be rewritten once one exists. The SIEM's forwarded copy stays independent evidence.

**Why not now.** Checked on 2026-11-10 with the lab's versions:

- OpenBao 2.7.1 has no post-quantum Transit key: `unknown key type ml-dsa` (also `slh-dsa`, `hybrid`).
- Vault 2.2.1 Community: `key type ml-dsa is only available in enterprise versions of Vault`.
- Go 1.27.3 has `crypto/mldsa` (FIPS 204), so `ligo` can verify ML-DSA locally, as it does ed25519.

`ligo` supports both OpenBao and Vault Community, so it cannot depend on a key type only Vault Enterprise has.

**Direction.** When OpenBao or Vault Community offers ML-DSA in Transit, sign each checkpoint with both keys, `ligo-audit` (ed25519) and a second ML-DSA key, and store both signatures. A checkpoint is valid only if both verify, so it is as strong as the stronger of the two. The schema does not change: `key_id` and `signature` are text. The `local-kek` signer can derive an ML-DSA key from the KEK as it does the ed25519 one.

## 15. Change request pruning

**Why.** `change_requests` only grows, as `audit_log` did. Every request, approved, rejected, withdrawn or expired, stays with its revisions, approvals and comments. Audit pruning (item 1) does not cover it: the user decided on 2026-11-11 to keep it out of that branch.

**What makes it hard.** Audit entries refer to change requests by `change_request_id`, and resources keep the request that last changed them. Deleting a request must not leave an audit entry or a resource pointing at nothing that explains it, unless the entry itself was pruned or exported first.

**Direction.** Prune only closed requests older than a retention, and only when every audit entry that names them has been pruned (item 1's boundary), so an exported audit file is the remaining record. Retired resources (001: never deleted) are a separate question.

## 18. A hint in a flow for the kind of TLS handshake

**Why.** A flow says `tls: true` and a `serverName`, and nothing about how TLS starts. PostgreSQL negotiates TLS inside its protocol (an `SSLRequest` first), and the workload API presents a SPIFFE SVID instead of a certificate for a name. A plain TLS check reports both as unreachable. netcheck v2.1.0 has the `postgresql` and `spire` checks for them (`netcheck/.specs/netcheck-tls-kinds.md`), but `flowcheck` cannot tell from a flow which to use, so the caller supplies the mapping (`flowcheck.WithProtocol`).

**Direction.** A field of the flow, set by the platform or the target that declares it (the PostgreSQL plugin says `postgresql`; ligo's own flows say `spiffe` with the expected SPIFFE ID), in the OpenAPI document and the protobuf contract, and read by `flowcheck` as the default mapping. It touches the plugin contract, the admin API and the SDK, so it needs its own spec, a decision on the values (a closed list or free text), and, until 1.0.0, no compatibility cost.

## 19. What `flowcheck` leaves out

Listed in `.specs/ligo-network-checks.md` §7 and decided on 2026-11-18, for the record with the reasons to revisit them.

- **A command line.** `ligo binding flows --check`, for an operator to see which flow a firewall blocks from the machine where the command runs. The SDK is the first user; the command waits for a request.
- **A check on the first fetch.** The SDK checks on demand only. Checking when a binding is first fetched costs connections the application did not ask for, which is why it is off.
- **CIDRs and ranges.** A destination that is a CIDR or a port range is skipped and reported, never expanded: expanding them would make the SDK scan a network.
- **DTLS, SSH and HTTP flows.** Flows declare TCP and UDP. netcheck can check the other protocols, but a flow has no way to say it wants them.
- **ICMP without privileges.** `WithICMP` needs `cap_net_raw` or a `ping_group_range` that includes the process's group; a better fallback is not planned.

## 20. What the Python SDK leaves out

Decided with `.specs/ligo-client-sdk-python.md` (2026-11-19).

- **asyncio (item 20).** The v1 client is synchronous and thread-safe; `watch` blocks. An `async` client, with `async for` on `watch`, doubles the surface and its tests, and waits for a user who needs it.
- **ICMP in flow testing (item 21).** Raw sockets need privileges that a Python program rarely has; unprivileged ICMP sockets need `net.ipv4.ping_group_range`. Go's `WithICMP` has both; Python's `check_flows` does TCP, TLS, PostgreSQL, SPIFFE and UDP.
- **PyPI (item 22).** The wheel and the sdist are attached to each GitHub release (`make py-build`, `release.yml`) and nothing else. **The user's condition (2026-11-19):** like the Terraform and OpenTofu registries (`terraform-provider-ligo/.specs/ligo-provider-backlog.md` item 2), published only when the ecosystem is stable and `ligo`'s API and the SDK's are no longer changing: a published version cannot be replaced, and users pin it. **Maven Central (added 2026-11-20)** follows the same condition: the Java SDK (`io.github.dihedron.ligo:ligo-client`) is attached to each GitHub release as a jar with its sources and javadoc, and goes to Maven Central in the same stable moment as PyPI and the Terraform and OpenTofu registries (Sonatype namespace `io.github.dihedron`, signed artifacts, a publish job in `release.yml`). Then: a PyPI project for `ligo-client`, trusted publishing configured for the repository, a publish job in `release.yml` run after the release's checks, and the README's install line changed from the release asset to `pip install ligo-client`.
- **gRPC (item 23).** The workload API also speaks gRPC, but `grpcio` has no hook for custom peer verification, and ligo's certificate is an SVID with no DNS name, so the SDK could not hold its rule that only ligo's SPIFFE ID is accepted. To revisit when `grpcio` can verify a URI SAN, or with a custom TLS layer.
- **Connection reuse and signing (item 24).** Each call opens its own connection, which is correct and simple at the SDK's call rates. Keep-alive pooling is possible later. The wheel is covered by the release's signed `checksums.txt`; sigstore attestation of the build is a further step.

## 25. A description and annotations on each binding

Asked for by the user (2026-11-19).

- **What.** Each binding gets a free-text `description` and an `annotations` map (the user first called it "metadata"; the admin response already uses that key for its envelope) of string keys to string values. Both are set through the admin API, the CLI, the UI and the Terraform provider, and both are sent to the client in the workload API (REST and gRPC) and inspectable there: the Go SDK's `Binding` and the Python SDK's `Binding` carry them.
- **To decide in the spec.** Whether they change through the change-request workflow like the rest of a binding, or are editable without approval (they grant nothing); limits (length of the description, number and size of keys and values, key charset); whether they are covered by the revision and the ETag, so a client sees a change; whether they appear in audit events and webhooks; the manifest (`apply`) and Terraform schema; and the threat model: the client gets text it did not write, so it is data and never instructions, and operators must not put secrets in it.
- **Order.** Best done before the Python SDK's wire types are final, so both SDKs and the golden documents shared by them (`api/testdata/workload/`) gain the fields together.

## 26. A more permissive license for the client libraries

Raised by the user (2026-11-19) while building the Python SDK.

The repository is AGPL-3.0. A workload that links `pkg/client`, `pkg/adminclient` or `ligo-client` becomes a combined work, so the AGPL's terms (source of the whole program, to its network users) reach the application, not only ligo. That is a barrier for the libraries' purpose. The usual answer is to license the client libraries separately and permissively (Apache-2.0 or MIT), and keep the server AGPL.

- **Leaning (the user, 2026-11-19).** MIT, for the client libraries and for all SDKs, the Python one and the later Java and JavaScript/TypeScript ones. Apache-2.0 is the alternative (a patent grant, a longer text).
- **To decide.** Which paths (`pkg/client`, `pkg/adminclient`, `sdk/python`, the generated `api/gen` and the protobuf contracts they use, `api/openapi`, `docs` examples); whether a path carries its own `LICENSE` file and SPDX headers; that the Go modules stay in one `go.mod` (a license per directory is allowed, but a package that imports `internal/` code of the server cannot be relicensed: `pkg/client` imports none today, which a test could enforce); the Python package metadata (`license` in `pyproject.toml`), the wheel's `LICENSE`, and the README's license section.
- **Constraints.** Only the copyright holders can relicense. `git shortlog` (2026-11-19) shows one author and dependabot (dependency bumps), so the author can decide alone. Dependencies keep their own licenses (`spiffe`, `cryptography`: Apache-2.0/BSD, compatible).
- **Done (2026-11-19).** MIT, `Copyright (c) 2026 Andrea Funtò`. A `LICENSE` file in `pkg/client`, `pkg/adminclient`, `internal/adminraw`, `api/proto/workload`, `api/gen/workload`, `api/openapi` and `sdk/python`; `SPDX-License-Identifier: MIT` in their hand-written sources (not in generated files, nor in `workload.proto`, which must equal the main spec's block); the package metadata; a License section in the README; `test/license` checks that every one has its file and that `pkg/client` and `pkg/adminclient` import nothing of the server. A new SDK adds its directory to the list in that test. Past releases stay under the license they were published with.

## 27. An admin API client in Python and Java

Asked for by the user (2026-11-20).

**Why.** The SDKs (Go, Python, Java) cover the workload API only: what a workload reads. The admin API (sources, targets, bindings, change requests, approvals, audit) has a Go client, `pkg/adminclient`, used by the CLI and the Terraform provider, and nothing else. Python is the language of Ansible, so a Python admin client is the base of item 28.

**What.** A package in `sdk/python` (to decide: the same distribution `ligo-client` with a second module, or `ligo-admin`), generated from or checked against `api/openapi/admin.v1alpha1.yaml`, with the semantics of `pkg/adminclient`: the admin authentication (to read from `internal/adminauth`: mTLS with an SVID or a token), the typed resources, the change-request flow with approvals, waiting for an applied change, manifests (`apply`). Java later, the same way, after the Java SDK. MIT license (item 26). Own spec, threat model and tests first (golden documents shared with Go, as the workload ones); published on PyPI and Maven Central with the rest (item 22).

## 28. An Ansible collection

Asked for by the user (2026-11-20).

**Why.** Operators install and configure ligo with the tools they already use. The collection (name to decide, e.g. `dihedron.ligo`) covers three areas, all idempotent, with check mode and `diff`:

- **Install and set up:** roles for the packages from the release, the `server.yaml` (platforms, plugins, the database, SPIRE and the TLS identity), the systemd unit, the migrations, the first start and the health check; the plugins' packages.
- **Manage the ligo server:** modules or roles for upgrades, `serve` reload, backups of the database, audit verification and export, and the readiness of a replica set (HA).
- **Manage resources:** modules `ligo_source`, `ligo_target`, `ligo_binding` (and their info modules), through change requests and approvals as the admin API requires, with the managed-resource lock of `.specs/ligo-managed-resources.md` so that Ansible and the UI do not fight.

**Needs.** The Python admin client (item 27), a spec with a threat model (secrets in playbooks, vault integration, approval identities: an automation account cannot approve its own change), a lab scenario (the lab already builds ligo on LXD VMs: a playbook installs it there), and the Ansible Galaxy publication with the rest (item 22).

## 29. Flow checks in netcheck, with Python and Java ports

**Why.** The flow-check rules (tcp, tls, postgresql SSLRequest, spire, udp; denied networks; resolve once and connect to the vetted address; at most 1,024 checks) now exist three times: `pkg/client` (Go), `sdk/python` and `sdk/java`. They must agree. The user's suggestion (2026-11-20): netcheck owns the semantics.

**Proposal.** netcheck holds the specification and a set of conformance vectors (flow, expected status and reason). It provides a Go library, and pure-Python and pure-Java ports that use only each language's standard library. The three SDKs depend on netcheck, or vendor its ports, and run the same vectors in their tests, so a change to the rules is made once and cannot drift.

**Open points.** Release and versioning of netcheck and the ports; whether the SDKs depend on it or embed it; how the vectors are shared (a JSON file in netcheck, copied to `api/testdata/`). Best done after the SDKs have settled, not before.
