# Introduction

`ligo` is the SPIFFE binding lifecycle service. It keeps a catalog of **sources** (groups of client workloads, each defined by a SPIFFE ID regex in one trust domain) and **targets** (resources on a **platform**, such as a schema of a PostgreSQL database), and manages the **bindings** that say a source may use a target at one of its access levels.

Every change is a **change request**, which each jurisdiction involved must approve. `ligo` then provisions an approved binding through a durable, three-stage pipeline of plugins, and attested workloads ask `ligo` which targets they may use and how to get their credentials.

This guide takes you from nothing to a first working binding. *Architecture and Design* explains why `ligo` works as it does; the *Operator's Guide* covers running it.

## What you install

| Package | Installs | Role |
| :---------- | :---------------- | :-------------------- |
| `ligo` | `/usr/bin/ligo`, `ligo.service`, the plugin directory, examples | The service and the command-line client |
| `ligo-plugin-postgres` | `/usr/lib/ligo/plugins/ligo-plugin-postgres` | Platform provider `postgres.v1`: one role per binding |
| `ligo-plugin-vault` | `/usr/lib/ligo/plugins/ligo-plugin-vault` | Secret store `vault.v1`: one credential per binding, in Vault or OpenBao |
| `ligo-plugin-openldap` | `/usr/lib/ligo/plugins/ligo-plugin-openldap` | Identity provider `openldap.v1`: one directory account per binding |

The built-in plugins need no package: the identity modes `svid.v1`, `target-local.v1` and `delegated-dynamic.v1`, and the store `none.v1`.

## What works together

A platform combines one identity provider, one platform provider and one secret store. With the shipped plugins, these are the combinations:

| Credential | Identity provider | Platform provider | Store and strategy |
| :------------------ | :---------- | :---------- | :------------ |
| A password `ligo` generates for a role of its own | `target-local.v1` | `postgres.v1` | `vault.v1`, `vault-static` |
| A password made on demand by Vault's database engine | `delegated-dynamic.v1` | `postgres.v1` | `vault.v1`, `vault-dynamic` |
| A directory account, verified by PostgreSQL through LDAP | `openldap.v1` | `postgres.v1` | `vault.v1`, `vault-static` |

## Known limits of this version

Read these before you plan a deployment.

- **PostgreSQL is the only platform provider.** Other targets need a plugin of your own, written with `pkg/pluginsdk`.
- **No `SVID` mode on PostgreSQL.** A workload cannot connect to PostgreSQL with its SVID directly: PostgreSQL's certificate authentication reads the CN or DN, never the URI SAN that holds a SPIFFE ID. `ligo` refuses `svid.v1` on a PostgreSQL platform.
- **The Vault store needs exact SPIFFE IDs.** It releases a credential to one exact SPIFFE ID, as Vault's globs could match more than `ligo` allows. A source whose regex covers many workloads, such as `w-[0-9]+`, is refused on such a platform with `422 source-not-exact`. Register one source per workload.
- **One password per role.** Between a rotation changing a password and the store holding the new one, the stored credential does not connect. The window lasts as long as those two stages.
- **`linux` only**, on `amd64` and `arm64`.
