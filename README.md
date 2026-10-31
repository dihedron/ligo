# ligo

`ligo` (pronounced "lee-go"; Latin for "I bind") is the SPIFFE binding lifecycle service. It manages sources, targets and the bindings that link them.

> **Under construction.** `ligo` is not released yet and is not ready for production. Interfaces, configuration and the database schema may still change without notice, and no backwards compatibility is kept before the first release.

## What it does

- A **source** is a group of client workloads, defined by a SPIFFE ID regex in one trust domain.
- A **target** is one resource on a **platform**, for example a PostgreSQL database, an Oracle schema or a Kafka topic. It has named access levels and the network flows needed to reach it.
- A **binding** says that a source may use a target at one of its access levels.

Every change is a change request. Each governance scope involved must approve it (maker-checker), as the governance policy requires. `ligo` then provisions an approved binding with a durable, checkpointed three-stage pipeline of plugins: an identity provider, the platform provider and a secret store.

The pipeline runs on DBOS and PostgreSQL. Plugins create the principal, grant the privileges on the target and set up credential delivery through Vault or OpenBao. Housekeeping loops repair drift, rotate static secrets, propagate source and target changes, and revoke expired bindings. Attested workloads then ask `ligo` which targets they may use and how to get their credentials.

## Status

Working:
- the core engine and storage;
- the plugin host;
- change requests and governance;
- the binding workflows, including break-glass;
- `ligo serve` with the admin API (`api/openapi/admin.v1alpha1.yaml`), the `ligo` CLI and webhook notifications.

Still to come:
- the workload API;
- the web UI;
- metrics;
- release packaging.

The specification is in [.specs/ligo_specification.md](.specs/ligo_specification.md).

## Build

```bash
make          # lint, then build into dist/
make help     # list the targets
```
