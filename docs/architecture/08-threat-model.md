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
| T-22 | `server.yaml` is modified, or an instance is changed to redirect wiring or loosen bounds. | 2, 6, 7 | `server.yaml` (plugin types, `instance_bounds`) root-owned, SHA-256 audited. Instances: four-eyes change requests in their jurisdiction, never automatic, delegated or break-glass; audited; per-binding snapshots. |
| T-22a | Two approvers point an instance at a host they control, to receive its bootstrap credential. | 4, 7 | The type's `instance_bounds`, root-owned: an endpoint outside it is refused; a changed `ca_pem` shows in the diff. |
| T-22b | An instance's row is edited in the database, bypassing change control. | 6 | Rows signed by the audit key; a row that does not verify is quarantined and reported. Residual: rollback to an earlier approved revision while the audit no longer holds a newer one. |
| T-22c | An instance selects the SVID of another instance of the same plugin process. | 3 | One SVID per instance, unless both allow sharing and share a jurisdiction, or the type's root-owned `shared_svids` lists the SVID. Residual: instances on a listed SVID read what its Vault role reads. |
| T-22d | A file path in an instance makes a plugin read a host file. | 4 | No file paths: certificates as `ca_pem` text. |
| T-22e | A secret is pasted into an instance's config. | 6 | Plugin schemas refuse unknown keys; bootstrap credentials stay references. |
| T-22f | Rapid instance changes keep replicas reconfiguring. | 3 | Four-eyes requests and rate limits; reconfiguration debounced; processes bounded by types × realms. |
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
| T-37 | The client SDK talks to a wrong server as `ligo`, or as the store; a tampered answer names a store the attacker controls, to collect the workload's JWT-SVID. | 1, 4 | `ligo` accepted only with its exact SPIFFE ID, over mTLS; the store only over TLS against the configured roots, with no redirect followed and no option to skip verification; `AllowedStores` pins the store addresses; the JWT-SVID carries the binding's audience. |
| T-38 | The SDK leaks a credential, or keeps it too long; a hostile answer exhausts memory. | 1 | The password is hidden in `String` and `LogValue`; errors carry statuses, never bodies; nothing is written to disk and credentials are not cached; store tokens dropped at 80 % of their TTL; bodies capped at 8 MiB. |
| T-39 | Many workloads polling overload `ligo`; a revoked binding keeps being used. | 1 | A 5 s floor on the poll interval, jitter, ETag, back-off, `Retry-After` and `RetryInfo`. The watch reports `Removed` within one interval and the store's policy is gone, so new reads fail. Residual: R-12. |
| T-40 | The admin client talks to a wrong server as `ligo`, and hands it the caller's LDAP password or an authorised request. | 2 | `https` only; the server verified by a CA pool or by its exact SPIFFE ID against a bundle, with TLS 1.3, and no option to skip it; the `HTTPClient`'s TLS settings are replaced, never merged; a redirect is an error, so credentials are never sent elsewhere; a proxy only tunnels, so a proxy that intercepts TLS fails the verification. |
| T-41 | The admin client leaks the password through a log, an error, a print of the client, or a trace. | 2 | The password is a `Secret` that prints as `[redacted]` with every verb and in `slog`, held in a closure so that a copy of the client shows none; errors carry the status and the problem's slug and detail, never headers or bodies, and the text of a response that is not a problem is never in an error; the client logs method, path and status only. |
| T-42 | A tool uses the admin client to approve its own change request, or a hostile server exhausts the tool's memory or time. | 2, 6 | The typed methods have no approve, decline, ratify, revert or break-glass, and a test fails if one appears; the server still requires a person and a distinct approver; answers are read through an 8 MiB limit, every call has the caller's context and a timeout, and a wait is bounded by its context. The package's raw call, which can reach a decision, is not a method: the CLI reaches it through `internal/adminraw`, which only code of this module can import, so the compiler stops the provider and the MCP server from making it. |
| T-43 | A stale read overwrites someone's change, or a retry files a change twice. | 2, 6 | An update, a state change and a deletion need the revision they are based on and fail before any request without one; a stale revision is `ErrConflict` and is never retried; a mutation is sent once, whatever the answer; only a GET is repeated. |
| T-44 | The generated code drifts from the contract, or a generator update changes behaviour. | 2 | The code is checked in and CI fails when it differs from the OpenAPI document (`make generate-check`); the generator is pinned by `go.mod` and `go.sum`; contract tests check that what the server sends satisfies the document's schemas; the exported API has its own names for the types. |
| T-45 | A person or another automation changes a managed resource through some write path. | 2, 6 | The check at filing and again in the applying transaction, for every write; a table test fails the build when a write has no decision; a trigger guards `managed_by`. |
| T-46 | Lock squatting: a hostile automation locks resources it can reach. | 2, 6 | Only `trusted_automation`, on every jurisdiction involved; adoption needs the sides, decided by people; release by an administrator; containment never blocked. |
| T-47 | A compromised owner SVID uses the lock to hide its changes. | 2, 5 | Every change is audited with `approvalReference` and `automationContext`; the refusals are audited; containment is not blocked. |
| T-48 | An orphaned lock: the automation is gone and nobody can change the resource. | 2, 6 | Release by an administrator: four eyes, people only, a justification, audited with the former owner. |
| T-49 | The lock blocks incident response. | 2 | Containment and break-glass are not blocked. |
| T-50 | The pipeline re-grants access that a person removed in an emergency. | 2, 6 | The hold, lifted only by a person; time never ends it. |
| T-51 | A break-glass change of a managed binding becomes permanent by ratification. | 2, 6 | Ratification is refused; the change reverts at its TTL. |
| T-52 | A race between a lock being set and a change being applied, or between two owners. | 2, 6 | The owner is checked in the applying transaction under the row lock; the lab races two automations for one name. |
| T-53 | The refusals flood the audit log. | 5 | `LOCK_VIOLATION_REFUSED` at most once a minute per principal and resource; `ligo_lock_violations_total` counts all. |
| T-54 | The owner column is changed outside a change request, in the database. | 6 | A trigger refuses the update; a test with the application's role. |
| T-55 | An operator puts a secret in a binding's description or annotations, which every matching workload now reads; or the text carries markup or control characters to a console or a page. | 1, 2, 3 | Documented as public to the binding's workloads; limits on length, count and characters, checked at filing; the UI escapes it; the SDKs never interpret it; changes need the consent of all sides, and the approval hash covers the text. Residual: `ligo` cannot recognize a secret. |
| T-56 | The Python SDK's private key reaches a disk: the standard library loads a key only from a file. | 1 | A 0700 directory and a 0600 file for the instant of the load, removed at once; the path is never logged. Residual: a crash in that instant leaves a file in a private temporary directory. |
| T-57 | The Python SDK sends its request to a server that is not `ligo`, because `ssl` has no hook for a peer's SPIFFE ID. | 1 | The ID is checked after the handshake and before the first byte; the SDK gives `connect`, never a bare context, and no option turns the check off; tested with a server of another ID. |
| T-58 | A secret in a Python `repr`, traceback, log, copy or pickle. | 1 | `Credential` hides its password in `repr`, `str` and `format`, refuses `pickle` and keeps it hidden in copies; errors carry a status or a type name, never a body. |
| T-59 | A compromised dependency of the Python SDK (`spiffe`, `cryptography`). | 1 | A bounded version range, `pip-audit` and CodeQL in CI, dependency review on pull requests, and the wheel built from the tag in the release workflow, covered by the signed `checksums.txt`. |
| T-60 | A workload uses `check_flows` to scan the network. | 1 | The destinations are those `ligo` vetted for the binding; link-local and cloud metadata ranges are denied; a name is resolved once and the vetted address is used; a CIDR or a range is never expanded; 1,024 checks at most. |

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
| R-12 | The SDK cannot close an application's connections: after a revocation, connections already open stay open until the application closes them, and a dynamic credential lives until its lease ends. |
