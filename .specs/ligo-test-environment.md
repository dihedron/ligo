# ligo — lab test environment

Oct 25, 2026 · @Andrea Funtò · **Draft for review**

## Overview

This spec defines the lab: a scripted, disposable test environment for ligo, built from LXD virtual machines on the lab host. It implements §11.1 of the main specification (*Lab environment*) one piece at a time, in **scenarios** that add to the same lab:

- **`storage`**: one PostgreSQL 16 server with the database roles of §4.1, reached over TLS with `sslmode=verify-full`. It serves the storage layer's integration tests (phase 2: migrations, database-enforced invariants, repositories, audit chain, resolution cache).
- **`identity`** (phase 3): two SPIRE trust domains, `prod.lab` and `test.lab`, each with its server and an OpenBao server, an LDAP directory, and the `ligo1` VM where `ligo` runs with one SPIRE agent per trust domain (Topology A of §10.5). It serves what needs real identities: sealing over OpenBao Transit with a JWT-SVID (ADR-07), the plugins (phase 4), administrator authentication (phase 7) and the workload API (phase 8).
- Later scenarios add the rest of §11.1 in the phase that first needs it: target databases (phase 4, with the first target plugin), the second `ligo` replica (phase 6), the network verification probe (phase 8) and the webhook receiver (phase 7). Each gets its own section here when it is designed. Vault joins OpenBao as a setting before the first release (§11.1 rule 5).

It follows the labs of openstack-spiffe and lxd-spiffe (`test/lab/` in those repositories) in structure and conventions, so that one operator can run all three: a `lab.sh` entry point, shell libraries in `lib/`, settings in `lab.env` overridable per machine, a git-ignored state directory, and acceptance tests in Go. Unlike them, its VMs run on the lab host's **LXD** (snap), not on libvirt. The three labs share no names, networks or files, and can run on the same host at the same time.

**Portability**: the lab runs on any Linux x86-64 machine with KVM and LXD. Every address, size and version is a setting with a default; a preflight check verifies the host and refuses to start with a clear explanation when something is missing.

**Non-goals**:
- Running in CI. CI runs the same integration tests against a `postgres:16` service container, without TLS (`.github/workflows/ci.yml`).
- Production deployment: the lab's PostgreSQL is configured for tests, not tuned.
- Installing LXD: the preflight checks that it is there and usable, and says what to run when it is not.

## Architecture

Everything lives in an LXD **project** `ligo-lab` (`features.images=false`, `features.profiles=true`, so nothing touches the `default` project), with a **storage pool** `ligo-lab` of its own and an LXD **managed bridge** `ligo-lab` with its own subnet and NAT. The lab host reaches the VMs over the bridge. The lab needs no `lxd init`: it creates everything it uses, and `down` removes it.

The lab host runs **one VM**:

| VM | OS (default) | Role | Default size (vCPU / RAM / disk) | Address |
| --- | --- | --- | --- | --- |
| `lxd` | Ubuntu 24.04 LTS (`ubuntu:24.04`, LXD VM) | The whole lab: an LXD of its own (snap, `LAB_INNER_LXD_CHANNEL`, refreshes held), whose instances are listed below | 4 / 6 GiB / 60 GiB | `.20` |

**Everything runs nested** inside the `lxd` VM, on its own LXD (KVM nesting on the lab host), so that the lab is one VM with one snapshot, and the lab host's LXD is never exposed: no HTTPS listener and no identities on it. In `identity`, the SPIRE servers attest `ligo1` through the inner LXD's API, as they would through the LXD that serves the workloads in production. The inner LXD has its own storage pool (`dir` on the VM's disk), and a managed bridge `inner` (`LAB_INNER_SUBNET`, default `10.253.0.0/24`, NAT through the `lxd` VM, DNS domain `ligo.lab`). Its instances, one per component:

| Instance | Kind | Role | Scenarios | Default size | Address |
| --- | --- | --- | --- | --- | --- |
| `pg` | container | PostgreSQL 16 from Ubuntu's archive | `storage` | 1 GiB | `.10` |
| `spire-prod` | container | SPIRE Server of `prod.lab`, and its OIDC discovery provider | `identity` | 512 MiB | `.20` |
| `spire-test` | container | SPIRE Server of `test.lab`, and its OIDC discovery provider | `identity` | 512 MiB | `.21` |
| `bao-prod` | container | OpenBao of zone `prod` | `identity` | 512 MiB | `.30` |
| `bao-test` | container | OpenBao of zone `test` | `identity` | 512 MiB | `.31` |
| `ldap` | container | OpenLDAP (`slapd` from Ubuntu's archive) | `identity` | 256 MiB | `.40` |
| `ligo1` | VM (nested) | The `ligo` host: one SPIRE agent per trust domain; runs `ligo` and the tests that need SVIDs | `identity` | 2 vCPUs / 2 GiB / 20 GiB | `.50` |

Inner instances are created from the lab image cached once in the inner LXD under local aliases (`lab-container`, `lab-vm`), so that creating one never queries the image remote. Servers, `pg` included, are system containers: they need no kernel of their own, and stay small and fast. `ligo1` is a virtual machine, as later the automation and workload nodes will be, because §11.1 rule 2 asks for separate kernels where node identity or process attestation is tested, and because its agents then attest exactly as on a production VM (through `lxd-agent`). Instances resolve each other as `<name>.ligo.lab`; every server certificate carries the name and the address as SANs. The lab host does not route to the inner network: `lab.sh` reaches the instances with `lxc exec` through the `lxd` VM, and the tests that need SVIDs run on `ligo1`, which reaches every server, `pg` included, directly on the inner bridge. The one exception is PostgreSQL, for the storage tests that run on the lab host: a proxy device of the inner LXD (`nat=true`, so that PostgreSQL sees the client's own address) publishes `pg`'s port 5432 on the `lxd` VM's lab address (`10.252.0.20:5432`). Nothing else is published.

**PostgreSQL**: listens on its inner address, port 5432; `pg_hba.conf` accepts only `hostssl` connections from the inner subnet and the lab subnet (the lab host, through the proxy), with `scram-sha-256`; the server certificate is issued by the lab CA, with `pg.ligo.lab`, its inner address and the `lxd` VM's lab address as SANs, so that clients verify it with `sslmode=verify-full` (§4.1) on either path. There is no `host` (non-TLS) rule.

**Database and roles** (§4.1): the database `ligo`, owned by `ligo_migrator`, and the four roles `ligo_migrator`, `ligo_app`, `ligo_reader` and `ligo_dbos`, each with a random password generated at `up`. Operations, not migrations, create them (§4.1), so the lab creates them with the same script CI uses: `test/lab/sql/roles.sql`, run as the `postgres` superuser with `psql` variables for the passwords. It creates the roles with `LOGIN` and nothing else, the database, and the `dbos` schema owned by `ligo_dbos`; the privileges on the `public` tables come from the migration's `GRANT`s.

**PKI**: a lab CA (ECDSA P-256, 10 years) and the server certificates (1 year), generated at `up` with `openssl` into the state directory and pushed into the VMs and instances with `lxc file push`. The CA's key never leaves the state directory.

**SPIRE** (`identity`): the release `LAB_SPIRE_VERSION` from GitHub (`spire` and `spire-extras`, linux-amd64-musl), verified against its published SHA-256, installed in `/opt/spire`.
- Each server holds one trust domain (`prod.lab`, `test.lab`): SQLite data store, disk key manager, a self-signed CA, node attestation by `lxd_iid` (below), and its bundle endpoint on `:8443` (for optional federation, Topology C, which stays off unless a test turns it on). Its OIDC discovery provider, from `spire-extras`, serves the trust domain's JWT keys on `https://spire-<zone>.ligo.lab:8008`, with a certificate from the lab CA, so that OpenBao can verify JWT-SVIDs.
- `ligo1` runs two agents, `spire-agent-prod` and `spire-agent-test`, as systemd units running as root, with Workload API sockets at `/run/spire/prod/agent.sock` and `/run/spire/test/agent.sock` (the paths of §8.1), and the `unix` workload attestor.
- **Node attestation with lxd-spiffe.** `ligo1` is an instance of the inner LXD, so its agents attest with the `lxd_iid` plugins of [lxd-spiffe](https://github.com/dihedron/lxd-spiffe) (`LAB_LXD_SPIFFE_VERSION`, default `0.2.0`): `lxd-server-plugin` on each SPIRE server, `lxd-agent-plugin` on `ligo1`, installed from the release's `.deb` packages after verifying the release's checksums file and its signature against lxd-spiffe's packaging key (`packaging/signing-key.asc`, fingerprint pinned in `lab.env`). Each server lists one LXD server, `inner`: the inner LXD, listening on its bridge only (`core.https_address` = the `inner` bridge's gateway, port 8443), pinned by its certificate fingerprint. Each SPIRE server has an LXD TLS identity of its own there (`spire-prod`, `spire-test`), in a group with only `can_view` and `can_view_instances` on the project `default` of the inner LXD and `can_view` and `can_access_files` on `ligo1` (proof mode `file_pull`). The two agents use separate proof directories (`/run/spire/lxd-prod`, `/run/spire/lxd-test`). There is no join token, and no other node attestor: if `lxd_iid` fails, the lab fails, and the failure is a finding for lxd-spiffe.
- An agent's SPIFFE ID is `spiffe://<td>/spire/agent/lxd_iid/inner/<volatile.uuid>`. Workload entries hang off a node alias per zone, `spiffe://<td>/node/ligo1`, with the selectors `lxd_iid:server:inner` and `lxd_iid:uuid:<ligo1's volatile.uuid>` (both of high trust in lxd-spiffe), so that they survive re-attestation; `up` recreates the alias when `ligo1` is rebuilt.
- Registration entries (`up`), children of the node alias: `ligo`'s core identity `spiffe://prod.lab/ns/sys/sa/ligo` on the prod agent and its bundle-access identity `spiffe://test.lab/ns/sys/sa/ligo-bundles` on the test agent (§10.5), both for the uid of the user `ligo` on `ligo1`; the plugins' entries come with phase 4. **Lab deviation**: the core entry selects on `unix:uid` only, not also on `unix:sha256`, because the binary that holds it changes with every test build; plugin entries (phase 4) select on both, as §10.5 requires.

**OpenBao** (`identity`): the release `LAB_OPENBAO_VERSION` from GitHub (the `.deb` for linux-amd64), verified against its published checksum. One server per zone, listening on `:8200` with TLS (lab CA), Raft storage on one node, initialized and unsealed by `up` (one unseal key; the unseal key and the root token stay in the state directory and are used only by `lab.sh`). `up` configures, as ligo's operations would:
- Transit at `transit/` with the key `ligo-interstage` (ADR-07), KV v2 at `kv/`;
- JWT auth at `auth/jwt-spiffe/`, trusting the zone's SPIRE OIDC discovery provider (`oidc_discovery_url`, lab CA);
- the role `ligo-sealer` (zone `prod` only): bound subject `spiffe://prod.lab/ns/sys/sa/ligo`, audience `https://bao-prod.ligo.lab`, policy `ligo-sealer`, which allows only `transit/encrypt/ligo-interstage` and `transit/decrypt/ligo-interstage`;
- the plugins' roles and policies come with phase 4.

**LDAP** (`identity`): OpenLDAP with `ldaps://ldap.ligo.lab:636` only (lab CA), base `dc=ligo,dc=lab`, seeded from `test/lab/ldap/seed.ldif`:
- `ou=users`: people of the scenarios (`alice`, `bob`, `carol`, `dave`, `marco`, `livia`, …), each with a random password stored in the state directory;
- `ou=services`: `ligo-admin-auth`, the service account ligo's admin authentication binds with (§8.1 `admin_auth.ldap`);
- `ou=groups`: the groups of the §8.1 example, for the scopes §11.1 asks for: viewers; operators, approvers and break-glass of the data centre `dc/corp-prod` and `dc/corp-test`; two tenancies `cloud/fin-01/payments` and `cloud/fin-01/hr`; the Information Security party `sec/infosec`;
- `ou=ligo-accounts`: the OU where the `openldap.v1` identity provider creates principals (phase 4), writable only by its service account.

**Tests on `ligo1`**: tests that need SVIDs carry the build tag `lab` and run on `ligo1` as the user `ligo` (uid recorded in `env.json`). `lab.sh deploy` compiles them on the lab host (`go test -c -tags 'integration lab'`, `CGO_ENABLED=0`, linux/amd64) and copies the binaries, one per package, to `/home/ligo/tests` on `ligo1`, with the lab CA at `/etc/ligo-lab/ca.crt`; `lab.sh test --on ligo1` runs each of them there with the environment of `lab.sh env --on ligo1`, and fails if any fails. That environment holds the PostgreSQL DSNs, `LIGO_TEST_CA`, the Workload API sockets (`LIGO_TEST_SPIRE_PROD_SOCKET`, `LIGO_TEST_SPIRE_TEST_SOCKET`), bao-prod's address and JWT audience (`LIGO_TEST_BAO_PROD_ADDR`, `LIGO_TEST_BAO_PROD_AUDIENCE`), and the LDAP URL and base (`LIGO_TEST_LDAP_URL`, `LIGO_TEST_LDAP_BASE`). Tests without the `lab` tag keep running on the lab host.

**Superuser access**: the tests never connect as `postgres`. Tests that need to act as a superuser do so through `lab.sh psql --superuser`, which runs `psql` inside the `pg` container over the Unix socket.

## Settings

`test/lab/lab.env` holds every setting with its default and documents it. A git-ignored `test/lab/lab.local.env` overrides it for one machine, and the environment overrides both:

- **Versions**: `LAB_IMAGE` (default `ubuntu:24.04`), the image of the VMs and of the inner instances, as `REMOTE:ALIAS`; `LAB_INNER_LXD_CHANNEL` (default `5.21/stable`), the inner LXD; `LAB_SPIRE_VERSION` (default `1.15.5`), `LAB_OPENBAO_VERSION` (default `2.7.1`) and `LAB_LXD_SPIFFE_VERSION` (default `0.2.0`), pinned; `up` verifies each download against the release's checksums.
- **Scenarios**: `LAB_SCENARIOS` (default `storage identity`).
- **LXD**: `LAB_PROJECT` (default `ligo-lab`), `LAB_NETWORK` (default `ligo-lab`), `LAB_SUBNET` (default `10.252.0.0/24`; the openstack-spiffe and lxd-spiffe labs use `10.250.0.0/24` and `10.251.0.0/24`), `LAB_STORAGE_POOL` (default `ligo-lab`), the pool the lab creates, with `LAB_STORAGE_DRIVER` (default `dir`; `dir`, `zfs` or `btrfs`) and, for `zfs` and `btrfs`, `LAB_STORAGE_SIZE` (default `80GiB`), the size of the loop file LXD creates for it. `dir` needs nothing on the host; `zfs` and `btrfs` take snapshots instantly and use the tools the LXD snap ships (`zfs` also needs the host kernel's ZFS module). The driver applies when the pool is created; `up` warns when the existing pool differs.
- **Sizes**: `LAB_LXD_CPUS` (4), `LAB_LXD_MEMORY` (`6GiB`), `LAB_LXD_DISK` (`60GiB`) for the `lxd` VM, `LAB_LIGO1_*` for `ligo1`, and the memory limit of each container. They apply when a VM or instance is created; `up` warns when one differs. The lab takes 4 vCPUs and 6 GiB of RAM on the lab host.
- **Locations**: `LAB_STATE_DIR` (default `test/lab/.state`, git-ignored): PKI, passwords, `env.json`, the DSN file.
- **Behaviour**: `LAB_ASSUME_YES` answers yes to `down`'s confirmation.

`up` records what it built in `env.json`: the scenarios, the image fingerprints, the inner LXD's version, the versions of PostgreSQL, SPIRE, lxd-spiffe and OpenBao, the CA's and the server certificates' SHA-256, and the addresses.

## Preflight

`lab.sh preflight` checks the host; `up` runs it first. Each check prints `ok`, `warn` or `fail` with what to do; all checks run, and any `fail` makes it exit non-zero:

- **Operating system**: Linux on x86-64.
- **Virtualization**: `/dev/kvm` present and usable.
- **LXD**: `lxc` installed, and the user can reach the daemon (otherwise: `sudo usermod -aG lxd $USER`, then a new login); LXD 5.21 or later; `LAB_STORAGE_DRIVER` is `dir`, `zfs` or `btrfs`, and for `zfs` the host's `zfs` kernel module loads; `LAB_STORAGE_POOL` absent or the lab's own. When the user is in the `lxd` group but the current session predates it, `lab.sh` runs its `lxc` commands through `sg lxd`. With `identity`: KVM nesting enabled on the lab host (`/sys/module/kvm_{amd,intel}/parameters/nested`), since `ligo1` is a VM inside a VM; nothing is asked of the lab host's LXD beyond what `storage` needs.
- **Resources**: vCPUs and RAM of the `lxd` VM, when not yet running, against what the host has free (plus 2 GiB for the host); free disk under LXD's directory (`/var/snap/lxd/common/lxd`) for the pool: the VMs' disks and one snapshot each with `dir`, `LAB_STORAGE_SIZE` with `zfs` and `btrfs`.
- **Software**: `openssl`, `jq`, and Go at the version `go.mod` requires.
- **Network**: `LAB_SUBNET` overlaps no host route and no other LXD network; `LAB_NETWORK` is absent or the lab's own; `LAB_INNER_SUBNET` differs from `LAB_SUBNET`.

## Lifecycle

`test/lab/lab.sh` is the entry point; each command is idempotent and prints what it does. `--scenario` defaults to `LAB_SCENARIOS`.

- `preflight`: see above.
- `up`: runs the preflight, creates the storage pool, the project, the network, the PKI and the passwords; launches the `lxd` VM and configures its inner LXD (pool, `inner` bridge, HTTPS on the bridge); launches the inner instances of the chosen scenarios with cloud-init and configures them (for `storage`: PostgreSQL with its certificate, `sql/roles.sql` and the proxy; for `identity`: see *Architecture*); waits until every server answers (PostgreSQL over TLS as each role); writes `env.json`; and takes the snapshot on the first success. A second `up` on a complete lab only verifies it.
- `env [--on ligo1]`: prints the environment the integration tests read, as `export` lines (`eval "$(test/lab/lab.sh env)"`), or with `--on ligo1` as `VAR=value` lines (what `test --on ligo1` passes to `lxc exec --env`): `LIGO_TEST_PG_MIGRATOR_DSN`, `LIGO_TEST_PG_APP_DSN`, `LIGO_TEST_PG_READER_DSN`, `LIGO_TEST_PG_DBOS_DSN`, each with `sslmode=verify-full` and `sslrootcert` pointing at the lab CA, through the proxy for the lab host and directly (`pg.ligo.lab`) with `--on ligo1`, which adds the other variables of *Tests on `ligo1`*. The same PostgreSQL variables, without TLS, are what CI sets.
- `test [-run REGEX] [packages]`: exports that environment and runs `go test -tags integration` (default packages `./...`).
- `deploy` / `test --on ligo1 [-run REGEX]`: build the `lab`-tagged tests and copy them to `ligo1`, or deploy and run them there (see *Tests on `ligo1`*).
- `snapshot` / `reset`: saves the `lxd` VM as the lab's baseline (inner instances stopped, VM shut down, disk only), or returns it to it and cold-boots it, starts the inner instances, unseals OpenBao and waits until every server answers. The baseline holds the empty `ligo` database with its roles, so `reset` is how a test session starts from a clean state (§11.1 rule 6).
- `psql [--as migrator|app|reader|dbos|--superuser] [args]`: a `psql` session, inside the `pg` container, as that role (default `migrator`) over TLS to its own address; `--superuser` connects as `postgres` over the Unix socket.
- `stop` / `start`: stop the inner instances and the `lxd` VM cleanly, or start them again as they were left (no revert). Inner instances have `boot.autostart`, so `start` and `reset` accept one that came up by itself meanwhile.
- `status`, `ssh <name> [command]`, `logs <name> [unit]`: inspection. `<name>` is `lxd` or an inner instance; `ssh` is `lxc exec` as root (through the `lxd` VM for an inner instance); `logs` shows its cloud-init log or a unit's journal.
- `down`: deletes the `lxd` VM with its snapshot (and so every inner instance), the network, the project, the storage pool and the state directory, after confirmation.

## Integration tests

Integration tests are Go tests behind the build tag `integration`, next to the code they test (for example `internal/store/migrate`). They read the `LIGO_TEST_PG_*` variables and fail, rather than skip, when the variables are missing, so that a run that tests nothing cannot pass. The tests share the `ligo` database: they apply the migrations themselves (idempotent), and a test that changes data either rolls its transaction back or uses names of its own, so that it never depends on what an earlier test left. `lab.sh reset` returns to an empty database between sessions; CI starts from one on every run. The tests that §11.1 calls acceptance scenarios and invariant suites (`test/acceptance`, `test/invariants`) use the same variables.

## Implementation plan for phase 3 (`identity`)

1. This section; the scenario plumbing (`--scenario`, sizes, `env.json`); the `lxd` VM with the inner LXD, and `pg` moved into it as a container with its proxy (the `storage` scenario then runs entirely nested; its tests and `reset` work as before) (preseed: pool, `inner` bridge, HTTPS on the bridge), and helpers to reach inner instances (`lab.sh ssh <instance>` through it); preflight for nesting.
2. SPIRE: the inner LXD's two restricted identities, both servers with lxd-spiffe and their OIDC discovery providers, `ligo1` with its two agents attested by `lxd_iid`, the node aliases and registration entries; `lab.sh spire <zone> <args>` (the server CLI). Done when the user `ligo` on `ligo1` fetches an X.509-SVID and a JWT-SVID from each agent.
3. OpenBao: both servers, initialized and unsealed, Transit, KV, JWT auth and `ligo-sealer`; `lab.sh bao <zone> <args>` (the CLI as root token). Done when `ligo1` logs in with its JWT-SVID and encrypts with Transit.
4. LDAP: `slapd` over `ldaps`, the seed; `lab.sh ldapsearch`. Done when `ligo-admin-auth` binds over TLS and finds a user's groups.
5. `deploy` and `test --on ligo1`; the first `lab`-tagged tests: `internal/sealing` against real Transit with a real JWT-SVID (the `JWTFetcher` from the SPIRE Workload API). Done (`fce2ee8`). **Deferred**: an LDAP smoke test in Go would bring `go-ldap` in before phase 7, which needs it; until then the shell `ldap_check` of `up`, `start` and `reset` covers the directory.
6. `snapshot`, `reset`, `stop`, `start`, `status` for the whole lab. The `lxd` VM's snapshot is taken with its inner instances stopped and the VM shut down (disk only: memory snapshots of nested VMs are not reliable), and `reset` cold-boots it, starts the instances and unseals OpenBao again.

## Implementation plan for chunk 2.1

1. This spec, and the main specification amended to `test/lab/` (§8.3, §11.1).
2. `lab.env`, `lib/common.sh`, `preflight`.
3. `up` / `down` / `status` / `ssh` / `logs` / `env` / `psql`, `sql/roles.sql`, PKI, snapshot / reset / stop / start. Done when `lab.sh psql --as app -c 'select 1'` works over TLS and `reset` restores an empty database.
4. The migration, the runner and its integration tests (chunk 2.1 proper), run with `lab.sh test`; the CI job with `postgres:16`.
