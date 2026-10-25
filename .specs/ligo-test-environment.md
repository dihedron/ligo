# ligo — lab test environment

Oct 25, 2026 · @Andrea Funtò · **Draft for review**

## Overview

This spec defines the lab: a scripted, disposable test environment for ligo, built from LXD virtual machines on the lab host. It implements §11.1 of the main specification (*Lab environment*) one piece at a time, in **scenarios** that add to the same lab:

- **`storage`** (this version): one PostgreSQL 16 server with the database roles of §4.1, reached over TLS with `sslmode=verify-full`. It serves the storage layer's integration tests (phase 2: migrations, database-enforced invariants, repositories, audit chain, resolution cache).
- Later scenarios add the rest of §11.1 (phase 3): two SPIRE servers and agents, Vault or OpenBao, LDAP, two `ligo` replicas, target databases, the network verification probe and the webhook receiver. Each gets its own section here when it is designed.

It follows the labs of openstack-spiffe and lxd-spiffe (`test/lab/` in those repositories) in structure and conventions, so that one operator can run all three: a `lab.sh` entry point, shell libraries in `lib/`, settings in `lab.env` overridable per machine, a git-ignored state directory, and acceptance tests in Go. Unlike them, its VMs run on the lab host's **LXD** (snap), not on libvirt. The three labs share no names, networks or files, and can run on the same host at the same time.

**Portability**: the lab runs on any Linux x86-64 machine with KVM and LXD. Every address, size and version is a setting with a default; a preflight check verifies the host and refuses to start with a clear explanation when something is missing.

**Non-goals**:
- Running in CI. CI runs the same integration tests against a `postgres:16` service container, without TLS (`.github/workflows/ci.yml`).
- Production deployment: the lab's PostgreSQL is configured for tests, not tuned.
- Installing LXD: the preflight checks that it is there and usable, and says what to run when it is not.

## Architecture

Everything lives in an LXD **project** `ligo-lab` (`features.images=false`, `features.profiles=true`, so nothing touches the `default` project), with a **storage pool** `ligo-lab` of its own and an LXD **managed bridge** `ligo-lab` with its own subnet and NAT. The lab host reaches the VMs over the bridge. The lab needs no `lxd init`: it creates everything it uses, and `down` removes it.

| VM | OS (default) | Role | Scenarios | Default size (vCPU / RAM / disk) | Address |
| --- | --- | --- | --- | --- | --- |
| `pg` | Ubuntu 24.04 LTS (`ubuntu:24.04`, LXD VM) | PostgreSQL 16 from Ubuntu's archive | `storage` | 2 / 2 GiB / 20 GiB | `.10` |

**PostgreSQL**: listens on the lab address only, port 5432; `pg_hba.conf` accepts only `hostssl` connections from the lab subnet, with `scram-sha-256`; the server certificate is issued by the lab CA, with the VM's address as IP SAN, so that clients verify it with `sslmode=verify-full` (§4.1). There is no `host` (non-TLS) rule.

**Database and roles** (§4.1): the database `ligo`, owned by `ligo_migrator`, and the four roles `ligo_migrator`, `ligo_app`, `ligo_reader` and `ligo_dbos`, each with a random password generated at `up`. Operations, not migrations, create them (§4.1), so the lab creates them with the same script CI uses: `test/lab/sql/roles.sql`, run as the `postgres` superuser with `psql` variables for the passwords. It creates the roles with `LOGIN` and nothing else, the database, and the `dbos` schema owned by `ligo_dbos`; the privileges on the `public` tables come from the migration's `GRANT`s.

**PKI**: a lab CA (ECDSA P-256, 10 years) and the server certificate (1 year), generated at `up` with `openssl` into the state directory and pushed into the VM with `lxc file push`. The CA's key never leaves the state directory.

**Superuser access**: the tests never connect as `postgres`. Tests that need to act as a superuser (AC-18 changes an audit row directly) do so through `lab.sh psql --superuser`, which runs `psql` inside the VM over the Unix socket.

## Settings

`test/lab/lab.env` holds every setting with its default and documents it. A git-ignored `test/lab/lab.local.env` overrides it for one machine, and the environment overrides both:

- **Versions**: `LAB_IMAGE` (default `ubuntu:24.04`), the image of the VMs, as `REMOTE:ALIAS`.
- **Scenarios**: `LAB_SCENARIOS` (default `storage`).
- **LXD**: `LAB_PROJECT` (default `ligo-lab`), `LAB_NETWORK` (default `ligo-lab`), `LAB_SUBNET` (default `10.252.0.0/24`; the openstack-spiffe and lxd-spiffe labs use `10.250.0.0/24` and `10.251.0.0/24`), `LAB_STORAGE_POOL` (default `ligo-lab`), the pool the lab creates, with `LAB_STORAGE_DRIVER` (default `dir`; `dir`, `zfs` or `btrfs`) and, for `zfs` and `btrfs`, `LAB_STORAGE_SIZE` (default `40GiB`), the size of the loop file LXD creates for it. `dir` needs nothing on the host; `zfs` and `btrfs` take snapshots instantly and use the tools the LXD snap ships (`zfs` also needs the host kernel's ZFS module). The driver applies when the pool is created; `up` warns when the existing pool differs.
- **Sizes**: `LAB_PG_CPUS` (2), `LAB_PG_MEMORY` (`2GiB`), `LAB_PG_DISK` (`20GiB`). They apply when the VM is created; `up` warns when the running VM differs.
- **Locations**: `LAB_STATE_DIR` (default `test/lab/.state`, git-ignored): PKI, passwords, `env.json`, the DSN file.
- **Behaviour**: `LAB_ASSUME_YES` answers yes to `down`'s confirmation.

`up` records what it built in `env.json`: the scenarios, the image fingerprint, the PostgreSQL version (`SHOW server_version`), the CA's and the server certificate's SHA-256, and the VM's address.

## Preflight

`lab.sh preflight` checks the host; `up` runs it first. Each check prints `ok`, `warn` or `fail` with what to do; all checks run, and any `fail` makes it exit non-zero:

- **Operating system**: Linux on x86-64.
- **Virtualization**: `/dev/kvm` present and usable.
- **LXD**: `lxc` installed, and the user can reach the daemon (otherwise: `sudo usermod -aG lxd $USER`, then a new login); LXD 5.21 or later; `LAB_STORAGE_DRIVER` is `dir`, `zfs` or `btrfs`, and for `zfs` the host's `zfs` kernel module loads; `LAB_STORAGE_POOL` absent or the lab's own. When the user is in the `lxd` group but the current session predates it, `lab.sh` runs its `lxc` commands through `sg lxd`.
- **Resources**: vCPUs and RAM of the VMs not yet running against what the host has free (plus 2 GiB for the host); free disk under LXD's directory (`/var/snap/lxd/common/lxd`) for the pool: the VMs' disks and one snapshot each with `dir`, `LAB_STORAGE_SIZE` with `zfs` and `btrfs`.
- **Software**: `openssl`, `jq`, and Go at the version `go.mod` requires.
- **Network**: `LAB_SUBNET` overlaps no host route and no other LXD network; `LAB_NETWORK` is absent or the lab's own.

## Lifecycle

`test/lab/lab.sh` is the entry point; each command is idempotent and prints what it does. `--scenario` defaults to `LAB_SCENARIOS`.

- `preflight`: see above.
- `up`: runs the preflight, creates the storage pool, the project, the network, the PKI and the passwords; launches the VMs with cloud-init (packages, PostgreSQL configuration), pushes the certificates, runs `sql/roles.sql`, waits until PostgreSQL answers over TLS as each role, writes `env.json` and the DSN file, and takes the snapshot on the first success. A second `up` on a complete lab only verifies it.
- `env`: prints the environment the integration tests read, as `export` lines (`eval "$(test/lab/lab.sh env)"`): `LIGO_TEST_PG_MIGRATOR_DSN`, `LIGO_TEST_PG_APP_DSN`, `LIGO_TEST_PG_READER_DSN`, `LIGO_TEST_PG_DBOS_DSN`, each with `sslmode=verify-full` and `sslrootcert` pointing at the lab CA. The same variables, without TLS, are what CI sets.
- `test [-run REGEX] [packages]`: exports that environment and runs `go test -tags integration` (default packages `./...`).
- `snapshot` / `reset`: saves the VMs as the lab's baseline (stopped, `lxc snapshot`), or returns them to it (`lxc restore`) and starts them again; `reset` then waits until PostgreSQL answers. The baseline holds the empty `ligo` database with its roles, so `reset` is how a test session starts from a clean state (§11.1 rule 6).
- `psql [--as migrator|app|reader|dbos|--superuser] [args]`: a `psql` session, inside the VM, as that role (default `migrator`); `--superuser` connects as `postgres` over the Unix socket.
- `stop` / `start`: stop the VMs cleanly, or start them again as they were left (no revert).
- `status`, `ssh <vm>`, `logs <vm> [unit]`: inspection. `ssh` is `lxc exec` into the VM as root; `logs` shows its cloud-init log or a unit's journal.
- `down`: deletes the VMs with their snapshots, the network, the project, the storage pool and the state directory, after confirmation.

## Integration tests

Integration tests are Go tests behind the build tag `integration`, next to the code they test (for example `internal/store/migrate`). They read the `LIGO_TEST_PG_*` variables and fail, rather than skip, when the variables are missing, so that a run that tests nothing cannot pass. The tests share the `ligo` database: they apply the migrations themselves (idempotent), and a test that changes data either rolls its transaction back or uses names of its own, so that it never depends on what an earlier test left. `lab.sh reset` returns to an empty database between sessions; CI starts from one on every run. The tests that §11.1 calls acceptance scenarios and invariant suites (`test/acceptance`, `test/invariants`) use the same variables.

## Implementation plan for chunk 2.1

1. This spec, and the main specification amended to `test/lab/` (§8.3, §11.1).
2. `lab.env`, `lib/common.sh`, `preflight`.
3. `up` / `down` / `status` / `ssh` / `logs` / `env` / `psql`, `sql/roles.sql`, PKI, snapshot / reset / stop / start. Done when `lab.sh psql --as app -c 'select 1'` works over TLS and `reset` restores an empty database.
4. The migration, the runner and its integration tests (chunk 2.1 proper), run with `lab.sh test`; the CI job with `postgres:16`.
