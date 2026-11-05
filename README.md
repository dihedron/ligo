# ligo

`ligo` (pronounced "lee-go"; Latin for "I bind") is the SPIFFE binding lifecycle service. It manages sources, targets and the bindings that link them.

> **First release.** `ligo` v0.1.0 makes no compatibility promise: interfaces, configuration and the database schema may still change.

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
- the external plugins, each with its own package: `ligo-plugin-openldap` (identity provider), `ligo-plugin-postgres` (platform provider) and `ligo-plugin-vault` (secret store, for Vault and OpenBao).

Known limits of v0.1.0:
- PostgreSQL is the only platform provider, and workloads cannot connect to it with an SVID directly (`.specs/ligo-postgres-plugin.md` §10);
- the Vault store releases a credential to one exact SPIFFE ID, so a source covering many workloads cannot use it (`.specs/ligo-vault-plugin.md` §4);
- there is no conformance suite that every plugin must pass; each plugin is tested on its own (`.specs/ligo-acceptance-matrix.md`, INV-07).

Everything is tested on a lab that reproduces the production architecture (two SPIRE trust domains, OpenBao, LDAP, PostgreSQL and target systems; see [.specs/ligo-test-environment.md](.specs/ligo-test-environment.md)). The lab suite passes against OpenBao 2.7.1 and HashiCorp Vault 2.2.1. The lab also runs a toy echo service for trying bindings by hand from the CLI or the web UI ([.specs/ligo-echo-target.md](.specs/ligo-echo-target.md)).

The specification is in [.specs/ligo_specification.md](.specs/ligo_specification.md).

## Build

```bash
make          # lint, then build into dist/
make help     # list the targets
```

## Install

Each release has deb and rpm packages and archives of `ligo` and of each plugin. [docs/operations.md](docs/operations.md) covers installing and running them.

### Verify a release

Releases are signed with the project's packaging key, [packaging/signing-key.asc](packaging/signing-key.asc), fingerprint `FB7DE97BAAFAA2A676CEE59A1B34E6A2A14CD06A`. Get the key from this repository, not from the release you are verifying.

- **The checksums file** covers every archive, package and SBOM of the release, and its signature (`.asc`) covers it:

  ```bash
  gpg --import signing-key.asc
  gpg --verify checksums.txt.asc checksums.txt
  sha256sum --check --ignore-missing checksums.txt
  ```

- **rpm packages** carry their own signature, which `rpm` and `dnf` check once the key is imported:

  ```bash
  sudo rpm --import signing-key.asc
  rpm --checksig ligo_<version>_linux_amd64.rpm   # must report "digests signatures OK"
  ```

- **deb packages** carry a `debsig` origin signature. `apt` and `dpkg` do not check it on a standalone package, so verify it with `debsig-verify`, after installing its policy for the key:

  ```bash
  sudo apt-get install debsig-verify
  sudo mkdir -p /usr/share/debsig/keyrings/1B34E6A2A14CD06A /etc/debsig/policies/1B34E6A2A14CD06A
  gpg --dearmor < signing-key.asc | sudo tee /usr/share/debsig/keyrings/1B34E6A2A14CD06A/debsig.gpg > /dev/null
  sudo tee /etc/debsig/policies/1B34E6A2A14CD06A/ligo.pol > /dev/null <<'POLICY'
  <?xml version="1.0"?>
  <!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
  <Policy xmlns="https://www.debian.org/debsig/1.0/">
    <Origin Name="ligo" id="1B34E6A2A14CD06A" Description="ligo packages"/>
    <Selection><Required Type="origin" File="debsig.gpg" id="1B34E6A2A14CD06A"/></Selection>
    <Verification MinOptional="0"><Required Type="origin" File="debsig.gpg" id="1B34E6A2A14CD06A"/></Verification>
  </Policy>
  POLICY
  debsig-verify ligo_<version>_linux_amd64.deb
  ```

Each release also carries `evidence-<commit>.tar.gz`, the logs and component versions of the lab run for that commit.
