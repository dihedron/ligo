# Components and trust boundaries

## Components

| Component | Responsibility |
| :------------ | :------------------------------------------ |
| Workload server | Read-only API, REST and gRPC. Answers from an in-memory cache, with Go's RE2. |
| Admin server | REST API and web UI, change requests, charter. |
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
| 2 | Administrators to `ligo` | The admin API and UI | SVID mTLS, LDAP, sessions, RBAC by jurisdiction |
| 3 | `ligo` to plugins | gRPC | Root-owned binaries, SHA-256 before every spawn, fd-based exec, AutoMTLS, one process per type and realm |
| 4 | Plugins to backends | SQL, LDAP, Vault | TLS verified, identifier grammars, privilege bounds, output validation |
| 5 | `ligo` to PostgreSQL | SQL | `verify-full`, four roles, triggers and checks in the database |
| 6 | Consent | People's decisions | Two-sided consent, distinct approvers, payload hash |
| 7 | The host | Files | `server.yaml` (plugin types and their `instance_bounds`, realms, policy) root-owned; its SHA-256 logged and audited at startup. Instances live in the database, signed |

## Plugins are less trusted

A plugin holds powerful credentials for its backend, but `ligo` does not take its word:

- Its output is validated against its schema, and every endpoint against the platform's `allowed_endpoints`, so a compromised plugin cannot point workloads at an attacker.
- Data it supplies is rendered as plain data, and never placed in `hx-*` attributes. This is tested with hostile values through every page.
- Only an error's `code` and fixed `public_message` are persisted.
- Identity is per process and realm: each instance must select exactly one SVID, in its realm's trust domain.

## Realms, jurisdictions and the charter

These are separate on purpose. A **realm** is technical: one trust domain, one SPIRE agent, one set of plugin processes. A **jurisdiction** is organisational: who decides. A flat data centre is a short jurisdiction; a cloud tenancy is a deeper one.

A realm is not a network zone. A network zone, such as a data centre segment or a cloud region, is where workloads run and what they can reach; one realm may serve workloads in several network zones, and one network zone may hold workloads of several realms.

Jurisdictions follow one set of rules. The **charter** is the set of rules every jurisdiction must comply with: how a workload's jurisdiction follows from its SPIFFE path, each jurisdiction's name prefix, which jurisdictions may bind to which and with whose further consent, and how account jurisdictions are formed. There is one charter per installation, in `server.yaml` under `charter:`. Jurisdictions say who decides; the charter says how jurisdictions are formed and how they may deal with each other. Every change request records the charter in force by its hash, and a change decided under a charter that has since changed is refused.

`ligo` verifies each trust domain against one authoritative bundle source, its own realm's agent or a declared federation through one realm. So an administrator of one SPIRE server cannot publish a forged bundle for another domain.
