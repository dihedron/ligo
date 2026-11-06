# Components and trust boundaries

## Components

| Component | Responsibility |
| :------------ | :------------------------------------------ |
| Workload server | Read-only API, REST and gRPC. Answers from an in-memory cache, with Go's RE2. |
| Admin server | REST API and web UI, change requests, governance. |
| Engine | Durable workflows on DBOS: apply, reapply, delete. |
| Background loops | Sweeper, reconciler, propagator, notification dispatcher. |
| Plugin host | Starts and checks plugin processes, calls them over gRPC with AutoMTLS. |
| PostgreSQL | `public`, the resources and audit log; `dbos`, the workflow journal. |
| Vault or OpenBao | Transit for sealing; credentials and per-binding policies in the store. |

## Listeners

The two listeners are separate so that they can be exposed differently, and so that a workload can never reach an administrative route. The workload listener is read-only. On the admin API, session cookies are ignored; on the UI, they are `__Host-`, `SameSite=Strict`, with a CSRF token, `Sec-Fetch-Site` checks and a strict Content Security Policy.

## Trust boundaries

| No. | Boundary | Crossed by | Protected by |
| :-- | :---------------- | :----------------------- | :------------------------------ |
| 1 | Workloads to `ligo` | SVIDs over the workload API | mTLS, or a JWT-SVID with an exact audience and bounded lifetime; bundle per trust domain |
| 2 | Administrators to `ligo` | The admin API and UI | SVID mTLS, LDAP, sessions, RBAC by scope |
| 3 | `ligo` to plugins | gRPC | Root-owned binaries, SHA-256 before every spawn, fd-based exec, AutoMTLS, one process per type and zone |
| 4 | Plugins to backends | SQL, LDAP, Vault | TLS verified, identifier grammars, privilege bounds, output validation |
| 5 | `ligo` to PostgreSQL | SQL | `verify-full`, four roles, triggers and checks in the database |
| 6 | Governance | People's decisions | Two-sided consent, distinct approvers, payload hash |
| 7 | The host | Files | `server.yaml` root-owned; its SHA-256 logged and audited at startup |

## Plugins are less trusted

A plugin holds powerful credentials for its backend, but `ligo` does not take its word:

- Its output is validated against its schema, and every endpoint against the platform's `allowed_endpoints`, so a compromised plugin cannot point workloads at an attacker.
- Data it supplies is rendered as plain data, and never placed in `hx-*` attributes. This is tested with hostile values through every page.
- Only an error's `code` and fixed `public_message` are persisted.
- Identity is per process and zone: each instance must select exactly one SVID, in its zone's trust domain.

## Zones and scopes

These are separate on purpose. A **zone** is technical: one trust domain, one SPIRE agent, one set of plugin processes. A **scope** is organisational: who decides. A flat data centre is a short scope; a cloud tenancy is a deeper one.

`ligo` verifies each trust domain against one authoritative bundle source, its own zone's agent or a declared federation through one zone. So an administrator of one SPIRE server cannot publish a forged bundle for another domain.
