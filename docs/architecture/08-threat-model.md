# Threat model

This is a STRIDE analysis, across the boundaries of *Components and trust boundaries*.

::: landscape

| ID | Threat | Boundary | Mitigation |
| :---- | :------------------------------------ | :-------- | :-------------------------------------------- |
| T-01 | A captured JWT-SVID is replayed. | 1 | Prefer mTLS; exact audience, `iat` required, bounded lifetime, clock skew, header redaction. Residual: R-04. |
| T-02 | A broad regex, or an in-place edit, gives a workload another's binding. | 1, 5 | Validation on the syntax tree (segment confinement); narrowing only; the active and current regex both apply. |
| T-03 | A pathological regex, or a request flood. | 1, 5 | RE2 only; length limit; in-memory resolution; per-SVID limits; reader statement timeout. |
| T-04 | LDAP injection, or an unauthenticated bind. | 2 | Empty credentials refused; name grammar; escaped filters; search-then-bind with exactly one match; rate limits; Basic off by default. |
| T-05 | A plugin injects script or htmx attributes through the UI. | 2, 3 | Declarative forms; `html/template`; no plugin data in `hx-*`; strict CSP with a per-response nonce and Trusted Types. |
| T-06 | Cross-site state change, or login CSRF. | 2 | `SameSite=Strict` `__Host-` cookies; CSRF token; `Sec-Fetch-Site` and `Origin` checks; cookies refused on the API. |
| T-07 | Secrets persisted in checkpoints, errors or status. | 5 | Sealing; fixed error messages; retention; a search for the e2e's passwords in the database and journals, after each lab run. |
| T-08 | An instance authenticates with another's SVID. | 3 | Process per type and realm; exactly one match; trust-domain and distinctness checks. |
| T-09 | A plugin binary is replaced. | 3, 7 | Root-owned, non-writable; no symlinks; SHA-256 before every spawn; fd-based exec; SPIRE `unix:sha256`. |
| T-10 | A delete leaves live credentials. | 4 | Visibility removed at once; state-driven cleanup, the access first; the bootstrap credential kept through an outage; `DELETE_FAILED` retried by itself when retryable; tags; sessions ended. |
| T-11 | Definitions or parameters inject SQL. | 4 | Grammars and quoting; privilege bounds checked three times; parameters cannot add privilege. |
| T-12 | An insider grants excessive access. | 2, 6 | Jurisdiction RBAC; two-sided consent; four-eyes; distinct approvers; payload hash. |
| T-13 | An actor denies a change; the audit is altered. | 2, 5 | Hash-chained, append-only audit; checkpoints signed with a key outside the database; pruning only through an exported checkpoint over a day old, by a database function the application cannot bypass; SIEM forwarding, the authoritative copy; request IDs. A compromised application can record an export it never took and prune early; the oldest-entry metric shows it. |
| T-14 | Direct database writes. | 5 | Separate roles; reader limited to a view; revalidation; immutable-column triggers. Residual: R-05. |
| T-15 | A plugin returns attacker-controlled endpoints. | 3, 4 | Output schema and `allowed_endpoints` validation. |
| T-16 | Secrets leak through plugin logs. | 3 | Redacting logger and secret types; host-side redaction; plugins log codes only. |
| T-17 | Fan-out overloads targets; a plugin hangs. | 2, 3, 4 | Per-instance semaphore; deadlines; bounded retries; concurrency limits; restart back-off. |
| T-18 | Two bindings collide on a name. | 4 | Names from the UUID; tags; foreign resources refused. |
| T-19 | A user removed from a group keeps their session. | 2 | Server-side sessions; groups re-read; timeouts. |
| T-20 | Admin views leak; Basic exposes passwords. | 2 | `viewer` by jurisdiction; `404` out of jurisdiction; automation uses SVIDs. |
| T-21 | SPIRE or a bundle is unavailable. | 1, 3 | Fail closed: `503`; plugin calls fail retryably. |
| T-22 | `server.yaml` is modified. | 7 | Root-owned; SHA-256 audited; per-binding snapshots; orphan check. |
| T-23 | The sealing key is compromised, or Transit is down. | 4 | Only `ligo-sealer`; no export; versions; short-lived blobs; unavailability fails attempts, and a retry rotates. |
| T-24 | A forged bundle for another trust domain. | 1, 3 | One authoritative bundle source per domain. |
| T-25 | A `trusted_automation` identity is misused. | 2, 6 | SPIFFE only; its own jurisdictions; a reference; separate execution contexts; audited. Residual: R-06. |
| T-26 | Break-glass is misused. | 2, 6 | People only, on every side; re-authentication; justification; automatic revert; ratification; paging. Residual: R-07. |
| T-27 | A theme misleads administrators. | 2, 7 | Root-owned; validated; hashes audited; SVG sandboxed. |
| T-28 | Target hijacking, or credential injection. | 2, 6 | Two-sided consent, enforced in the database. |
| T-29 | A workload is registered under another tenancy. | 1, 6 | A registrar tenants cannot influence. Residual: R-08. |
| T-30 | Bypass of cross-boundary consent. | 2, 6, 7 | Interconnection policy, default deny; parties; distinct approvers; policy hash, audited. |
| T-31 | Name squatting and probing. | 2 | Name prefixes; `404` out of jurisdiction. |
| T-32 | A rogue or misleading target. | 2, 4, 6 | Platform owner's consent; privilege bounds; canonical privileges shown to reviewers. |
| T-33 | The catalog discloses systems. | 2 | `PRIVATE` by default; filtered by policy. |
| T-34 | Overlapping sources. | 2, 6 | Overlaps reported to reviewers. Residual: R-10. |
| T-35 | Misleading flows. | 2, 4 | Destinations within `allowed_endpoints`; both owners consent. |
| T-36 | Login lockout. | 2, 4 | The per-user limit is per address, and the limit from any address is ten times higher, so a lockout needs many addresses. |

:::

## Accepted residual risks

| ID | Risk |
| :--- | :-------------------------------------------------------------- |
| R-01 | Partial convergence towards a new revision while an attempt is in flight or failed. |
| R-02 | Up to `full_reload_interval` of staleness if a notification is lost. |
| R-03 | A credential-switch window between Stage 2 and Stage 3 on rotation, as PostgreSQL has no dual passwords. |
| R-04 | JWT-SVID replay within its lifetime, in `jwt_svid` mode. |
| R-05 | Compromise of the `ligo_app` database role. |
| R-06 | For delegated requests, review quality depends on the upstream process, which `ligo` cannot verify. |
| R-07 | A break-glass change can be misused within its TTL. Emergency deletes are not reverted. A plugin outage extends an expired `UPDATE`. |
| R-08 | Jurisdictions are only as trustworthy as the assignment of SPIFFE paths in SPIRE. |
| R-09 | A rule with `distinct_approvers: false` lets one person approve both sides for its pairs. |
| R-10 | Two sources of one jurisdiction may overlap. Overlaps are reported, not refused, as a narrower source for a subset is legitimate. |
| R-11 | Between a change's commit and each binding's re-apply, a platform can lag behind what was approved. For narrowed grants, old privileges remain until then. |
