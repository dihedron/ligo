# Prerequisites

## Services

| Service | Needed for | Tested with |
| :------------- | :------------------------ | :------------- |
| PostgreSQL | `ligo`'s own database, with TLS | 16 |
| SPIRE | `ligo`'s identity, its plugins' and its workloads', one agent per zone on each `ligo` host | 1.15 |
| Vault or OpenBao | Transit sealing, and the plugins' credentials | Vault 2.2, OpenBao 2.7 |
| An LDAP directory | Signing administrators in; optional when they all use SVIDs | OpenLDAP |
| PostgreSQL, as a target | What the bindings give access to | 16 |

`ligo` needs an external PostgreSQL that it can reach with `sslmode=verify-full`. Its connections must not go through a pooler that hides or reuses `application_name`: recovery of a lost replica relies on it.

## Network

| From | To | Port | Purpose |
| :---------- | :------------ | :---- | :---------------------- |
| Workloads | `ligo` | 8443 | Workload API, REST and gRPC, over mTLS or with a JWT-SVID |
| Administrators, automation | `ligo` | 9443 | Admin API and web UI |
| Prometheus | `ligo` | 9090 | Metrics, in plain HTTP: bind to a loopback or management address |
| `ligo` | PostgreSQL | 5432 | Its database |
| `ligo` | Vault or OpenBao | 8200 | Transit sealing |
| Plugins, on the `ligo` host | Vault or OpenBao, targets, directory | as configured | Provisioning |
| Workloads | Vault or OpenBao, targets | as configured | Reading credentials, then connecting |

## What to decide first

- **Zones and trust domains.** A zone is one trust domain with one SPIRE agent socket on the `ligo` host. Decide which domains are zones of their own, and which `ligo` only verifies through federation. A single zone is the simplest start.
- **Governance scopes.** A scope is who decides: `dc/corp-prod`, `cloud/fin-01/payments`. Every source, target and platform has one owner scope. Decide how a trust domain's SPIFFE paths map to scopes: one fixed scope for a data centre, or a template over the path for tenancies.
- **Accounts.** To host many tenants on shared platforms, decide the shape of their scopes and of their directory groups once, for all of them. See "Accounts" in the chapter on configuring `ligo`. Without `governance.accounts`, `ligo` has no accounts.
- **Who approves.** Which scopes require an approver, and which LDAP groups or SPIFFE IDs hold the roles.
- **How many replicas.** Replicas share one database. Each needs a stable ID of its own.
