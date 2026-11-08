# ligo: backlog

Work agreed for later, with what is known so far. An item here is not a specification: each needs its own spec, approved, before any code (AGENTS.md rule 1). Update this file when an item is added, started or done.

| No. | Item | Recorded | Status |
| :-- | :------------------------------------ | :--------- | :---------------- |
| 1 | Audit pruning | 2026-11-08 | Not started |
| 2 | Pluggable authentication | 2026-11-08 | Not started |
| 3 | The fix for GO-2026-5932 | 2026-11-08 | Open: decide |
| 4 | Manual test A-1 | 2026-11-07 | Open: in-person session |
| 5 | Lab work for v0.2.0 | 2026-11-07 | Waiting for the lab host |
| 6 | Product examples in the Planning for Deployment Guide | 2026-11-08 | Later release |
| 7 | Client SDKs (Go, then Python and Java) | 2026-11-08 | Not started |
| 8 | Terraform and OpenTofu provider | 2026-11-08 | Not started |
| 9 | A map of the `ligo` topology, and a discovery protocol | 2026-11-08 | To explore |

## 1. Audit pruning

**Why.** `audit_log` only grows. Every state change, propagation and workflow outcome adds a row, so on a busy installation the table grows without bound, and with it backups, restores and `audit verify`.

**What makes it hard.** Pruning has to keep the two properties the audit exists for.

- **Append-only (T-13).** The trigger `trg_audit_no_update` in `migrations/001_init_schema.sql` refuses every `UPDATE` and `DELETE`, and `ligo_app` holds only `SELECT` and `INSERT`. A pruning path must not open a way to delete arbitrary rows.
- **The hash chain (§4.3).** Each row's `entry_hash` covers the previous row's hash, starting from 64 zeros. `GET /v1/admin/audit/verify` recomputes from the first row, so deleting the oldest rows breaks verification unless the boundary is kept.

**What is pruned already.** Finished DBOS workflows, after `storage.dbos.workflow_retention` (the sweeper's `retain`, `internal/workflows/sweeper.go`), and delivered or abandoned webhooks after 30 days (`internal/notify/notify.go`). Not pruned: `audit_log`, `change_requests` and retired resources. `001` says retired resources are never deleted, as audit entries and SPIFFE paths refer to them; whether they are in scope is to decide.

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
- Roles come from LDAP groups (governance rules, and for accounts one rule for all of them).
- Web UI sessions live in the database. Group membership is re-checked against LDAP every `authz_recheck_interval` (default 5 minutes, `internal/server/ui/session.go`). If the directory cannot be reached, the request fails and the session is kept: it fails closed.
- Automation signs in with an SVID over mTLS, and is not affected.

**What the design must cover.**

- **Break-glass** demands fresh re-authentication with a password and a live group check (ADR-12 rule 1). With SSO this becomes a step-up at the identity provider: OIDC `max_age` or `acr`, or a second factor.
- **The CLI** needs a flow without a password: the OIDC device flow, or a Kerberos ticket.
- **Where groups come from.** If roles come from identity-provider claims instead of LDAP, the periodic re-check needs a new source, or sessions need a shorter life.
- **Per method:** rate limits, `SESSION_LOGIN_FAILED` auditing, and rows of the threat model (T-36 and the session threats).
- Authorisation stays as it is: roles on scopes. Only where the principal and its groups come from becomes pluggable.

## 3. The fix for GO-2026-5932

**Why.** GO-2026-5932 (the unmaintained `golang.org/x/crypto/openpgp`) was accepted on 2026-10-29, because no fix existed and `ligo` never calls it: `x/crypto` comes in through `go-ldap` (§12, EXT-13).

**What changed.** On 2026-11-08 `govulncheck` names a fix: `golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2`, a pseudo-version, so an untagged commit. The symbol scan still reports that `ligo` is affected by 0 vulnerabilities.

**To decide.** Bump to the pseudo-version now, or wait for a tagged `x/crypto` release and bump then. Either way, the acceptance note goes once the finding is gone.

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

**What exists.** The admin API is described in `api/openapi/admin.v1alpha1.yaml` (48 paths). Every mutation is a change request, with optimistic concurrency (`expectedRevision`) and approval bound to the exact payload (`payloadSha256`). Automation signs in with an SVID, and a `trusted_automation` principal can approve sides of its own scopes by delegation, with a reference to an upstream approval (ADR-11).

**What makes it different from most providers.** An `apply` does not change the resource: it files a change request, which may wait for people of another scope to approve it. The design must settle:

- what `apply` waits for (the request filed, applied, or the binding `ACTIVE`), with time-outs, and what a later `plan` shows while a request is pending;
- how a pipeline's own review becomes the upstream approval of a `DELEGATED` side, and how that reference is checked;
- drift: what `plan` shows when people changed a resource through the UI;
- read-only data sources for platforms and realms, which live in `server.yaml`, not in the API;
- one provider for Terraform and OpenTofu (the plugin protocol is shared), and its own repository and release.

## 9. A map of the `ligo` topology, and a discovery protocol

**Why.** With several installations (chapter 5 of the Planning for Deployment Guide), nobody sees the whole picture. A visual map would show, across installations: the realms and federated trust domains of each, who trusts whom, which governance scopes each one serves, and a few statistics about each one's bindings (counts by phase, failures, expiries).

**What exists.** Each installation knows its own part: realms, federated domains and accepted trust domains in `server.yaml`; platforms and their scopes through the admin API (read-only); bindings by phase and realm as metrics (`ligo_bindings{phase,realm}`). Nothing today connects installations to each other.

**To explore.**

- **Transport.** A request-reply protocol over gRPC, where each installation answers queries about itself, or a gossip membership library such as `hashicorp/serf`, where installations find each other and spread summaries. Gossip fits finding peers; gRPC fits authenticated, audited queries. A mix is possible.
- **Who may see the map.** The topology is sensitive: it tells an attacker where trust is, and who can approve what. Answers go only to a more trusted subset of servers, authenticated by SVID over mTLS, with a dedicated role, and every query is logged.
- **What is shared.** Counts and names, never resources, scopes' members or secrets; whether scope names themselves may leave an installation is to decide.
- **Where the map is drawn**: the web UI of a designated installation, or a separate read-only tool.
