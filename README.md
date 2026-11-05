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
- `ligo serve` with the admin API (`api/openapi/admin.v1alpha1.yaml`), the `ligo` CLI and webhook notifications;
- the workload API (REST and gRPC), which attested workloads use to find their bindings and network flows;
- the web UI (htmx), including the binding wizard, approvals and break-glass, with operator theming;
- Prometheus metrics on their own listener (`server.metrics_listener`, default `127.0.0.1:9090`);
- the `openldap.v1` identity provider, `ligo-plugin-openldap`, with its own package ([docs/operations.md](docs/operations.md)).

Still to come, before the first release (v0.1.0):
- a pass over every acceptance scenario of the specification;
- the systemd unit in the package, and the rest of the operations guide.

Everything is tested on a lab that reproduces the production architecture (two SPIRE trust domains, OpenBao, LDAP, PostgreSQL and target systems; see [.specs/ligo-test-environment.md](.specs/ligo-test-environment.md)). The lab suite passes against OpenBao 2.7.1 and HashiCorp Vault 2.2.1. The lab also runs a toy echo service for trying bindings by hand from the CLI or the web UI ([.specs/ligo-echo-target.md](.specs/ligo-echo-target.md)).

The specification is in [.specs/ligo_specification.md](.specs/ligo_specification.md).

## Build

```bash
make          # lint, then build into dist/
make help     # list the targets
```
