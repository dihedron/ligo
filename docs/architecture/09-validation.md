# Validation

## The lab

Everything is tested on a lab defined as code, with real components and production security settings: two SPIRE trust domains, Vault and OpenBao, two `ligo` replicas behind a load balancer, PostgreSQL, OpenLDAP, a collector and a webhook receiver, in virtual machines and containers. TLS is verified everywhere, sealing uses real Transit, and plugin binaries are root-owned with checksums.

A release's evidence comes from one command that refuses a modified tree, destroys the lab, builds a new one, and runs every suite on OpenBao and then on Vault. Its logs and component versions are published with the release, as `evidence-<commit>.tar.gz`.

## What the suites show

| Suite | Shows |
| :---------------- | :---------------------------------------- |
| Unit and integration | The engine, governance and each plugin, on a real PostgreSQL. |
| `serve test` | A real service: lifecycle, the workload API, the CLI, restarts, the plugins end to end, the four topologies; then a search for the passwords in the database and journals. |
| `serve test-ha` | Maintenance across replicas, concurrent approvals applied once, a replica killed and one frozen mid-workflow. |
| `serve test-otel` | Traces reach a collector across replicas, with no secrets or error text. |
| `serve test-webhook` | Signed notifications, a receiver down, and scope filters. |
| `serve test-faults` | The secrets backend and PostgreSQL stopped under load. |
| Browser tests | Forms, CSP, hostile data through every page. |

## The acceptance matrix

92 acceptance scenarios and 26 invariants are tracked, each with its tests and level, in `.specs/ligo-acceptance-matrix.md`. All scenarios are covered, and 25 invariants. Each of three tests below enforces completeness: a new route without an audit entry, or a new page without hostile-data coverage, fails.

- **Every state-changing route audits**: a real request to each, its audit entry found by request ID.
- **Hostile data stays inert**: hostile values in every string of every page, then the parsed document searched for elements, handlers and URLs.
- **The documents are complete**: every configuration key, problem slug, plugin code and metric.

## What has not been shown

- **INV-07 is partial.** Each plugin is tested on its own; there is no conformance suite that every plugin must pass.
- **Long outages.** PostgreSQL stopped for 10 s, not hours.
- **Scale.** The lab shows behaviour, not load limits.
- **A registrar.** The lab mints tenancy workloads itself, so the assumption of T-29 is stated, not tested.
- **Cross-domain credential reads.** A workload of another trust domain receives its binding from `ligo`, but the lab's store trusts one domain's tokens, so its login is refused.
- **Package upgrades on a real host**, and signature checks with `debsig-verify`, before the first release exists.
