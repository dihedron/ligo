# ligo — the soak

- **Version:** 1.5 (2026-11-10): a rolling restart paired with a fault that keeps ligo from starting stops the roll instead of ending the scheduler. 1.4 (2026-11-09): DAMAGE, SOAK_EXCLUDE, SOAK_NIGHT, faster SVID renewal, SK-1 from the fault's end. 1.3 (2026-11-09): fault markers, recovery and drift verdicts, deferred faults. 1.2 (2026-11-08): SK-2 sampled, SK-10 liveness, the abuse action, the four-eyes mutant. 1.1: one workload per account; binding updates instead of target updates; SVID renewal
- **Status:** approved plan, harness to build
- **Scope:** test tooling only. Nothing here ships, and the soak adds no product code. A product change it reveals goes through the main spec, with a test first.

## 1. Purpose

The release-run proves each behaviour once. The soak proves that the behaviours still hold after hours of load, faults and recovery. It answers four questions:

1. Does any invariant ever break, even for a moment, under load and faults?
2. Does every fault end with recovery inside its limit, with nobody stepping in?
3. Does anything drift (memory, connections, processes, tables, latency) once warm-up is over?
4. Can every failure be reproduced from its seed?

It runs on the lab of `.specs/ligo-test-environment.md`, with every scenario up: `storage identity ha lb otel vault webhook`. It reuses the patterns of `lab.sh serve test-faults` and `test-accounts-chaos`:
- bash in `test/lab/lib/soak.sh` causes the faults on the inner instances;
- `lab`-tagged Go tests run on ligo1 (`serve_e2e`) and drive the API.

## 2. Pieces

| Piece | Where |
| :-- | :-- |
| Orchestration: `lab.sh soak run`, `prove`, `report` | `test/lab/lib/soak.sh` |
| Generator: `TestSoak` | `internal/command/serve/serve_soak_lab_test.go` (`lab` tag) |
| Checker: SK-1 to SK-10 | `internal/command/serve/soak_invariants_lab_test.go` (`lab` tag) |
| Mutants | `test/lab/soak/mutants/*.patch` |
| Evidence | `test/lab/.evidence/soak-<commit>-<label>/` |

The generator and the checker live in package `serve`, so they reuse its lab helpers: `newAdmin`, `admin.try`, `approveAll`, `decide`, `breakGlass`, `storeCredential`, `ledgerConn`, `selectFrom` and `waitMarker`.

## 3. Settings

| Variable | Default | Meaning |
| :-- | :-- | :-- |
| `SOAK_SEED` | the current time in nanoseconds, printed | Seeds the generator and the fault scheduler |
| `SOAK_DURATION` | `15m` | How long the load runs |
| `SOAK_FAULTS` | `none` | `none`, `single` (one at a time) or `all` (single, then combinations) |
| `SOAK_RACE` | `0` | `1`: `ligo` is built and deployed with `-race` |
| `SOAK_MAX_CONNS` | unset | Sets `storage.postgres.max_conns` in the lab's `server.yaml` |
| `SOAK_ACCOUNTS` | `20` | Accounts the generator uses at once, each with one workload |
| `SOAK_EXCLUDE` | empty | Faults left out of the catalogue, by name: a known defect's faults, while it is being fixed |
| `SOAK_NIGHT` | `0` | `1`: the night's resources, applied after the install (§9) |

`lab.sh soak run` writes every setting, the commit and the lab's versions to `settings.json` in the evidence directory. The tree must be clean, as for the release-run, so that the evidence names what ran.

## 4. The generator

`TestSoak` runs on ligo1 until `SOAK_DURATION` ends, then stops the load, waits for convergence (SK-7's limit) and checks every invariant one last time.

### 4.1 Actors

- **People:**
  - each account's approvers, from the directory groups that `soak.sh` creates (`ou=soakNN`), as in `serve_chaos_directory`;
  - the platform approver;
  - an operator holding break-glass;
  - the account administrator who registers and retires accounts.
- **Workloads:** one per account, `spiffe://prod.lab/acct/<account>/project/p1/sa/w0`. Its account's source names exactly that ID, because the store's `vault-static` strategy matches subjects exactly (OI-1, `422 source-not-exact`).
- **SVIDs:** `soak.sh` mints each workload's X.509-SVID and JWT-SVID, and the X.509-SVIDs of `ada`, `peter` and `rita`.
  - Renewal: the X.509-SVIDs every 5 minutes, with a 1-hour TTL; the JWT-SVIDs every minute, since SPIRE caps them at 5. A SPIRE outage of 10 minutes then leaves them valid.
  - SK-2 skips a credential whose workload's JWT-SVID is older than 4 minutes: the harness, not ligo, failed to renew it.
  - The generator re-reads them on every request or TLS handshake.
- **Registration first:** the setup registers every account before anyone files. An LDAP person's roles are read when their session starts, so an account registered later only counts at the session's re-check.

### 4.2 Actions

Each tick, every 2 seconds, draws one action from the seeded source, with these weights:

| Weight | Action |
| :-- | :-- |
| 25 | A workload reads its bindings, takes its credential from the store and connects to its tenancy |
| 15 | Create a binding (one in three across accounts), then decide its sides, by the right people. Pairs already bound are skipped |
| 10 | Revoke a binding (DELETE, owner alone) |
| 8 | Update a binding's purpose |
| 8 | Register a source matching no workload, then retire it |
| 6 | Decline or withdraw a pending change |
| 5 | Rotate a binding's credential (REAPPLY) |
| 4 | Break-glass a binding; half are ratified, half are left to be reverted |
| 3 | Register an account |
| 2 | Retire an account: its sources and targets first, then the registration |
| 10 | Read-only admin calls: lists, the catalog, the charter |
| 3 | Abuse: the requester approves its own binding, then one approver tries SOURCE and TARGET. Both must be refused; one accepted is an SK-4 violation at once. The binding is then decided properly |

Each workload also runs in its own loop, once every 30 seconds, beside the ticks. Live bindings are capped at 200: above the cap, create actions turn into revocations.

The tenancies are fixed, two per account. The platform team creates schemas outside ligo, so the soak cannot publish new ones at run time.

Directory changes are not the generator's: the test binary holds no directory credentials. `soak.sh` moves people into and out of approver groups as an operation, alongside the faults (§6).

### 4.3 History

Every action, decision, fault start, fault end and invariant check is one JSON line in `history.jsonl`, with these fields:
- `t`: the time, in RFC 3339 with milliseconds;
- `seq`: the sequence number;
- `kind`;
- `actor`;
- the resource names;
- the HTTP status;
- the latency in milliseconds;
- the load of the lab VM, sampled every minute.

No secret ever goes in the history. A credential appears only as the user name.

## 5. Invariants

The checker runs every 60 seconds, and again 30 seconds after each fault ends. A violation is written to the history with the evidence that showed it. The run goes on and reports at the end. A run with any violation fails.

| ID | Must hold | How it is checked |
| :-- | :-- | :-- |
| SK-1 | A revoked binding delivers nothing, and its role is gone, within 2 minutes of the revocation being applied | Workload: the binding is absent from its list. Target admin: `pg_roles` no longer has the role |
| SK-2 | Every `ACTIVE` binding's current credential connects | 20 live bindings drawn each minute, every one at the end: the store read as its workload does, then a connection as that user that reads its tenancy. A failure counts only if the binding is still `ACTIVE` afterwards |
| SK-3 | No credential reads another tenant's schema | With each credential of SK-2: `select` on another account's schema must be refused (`42501`) |
| SK-4 | No `APPLIED` change was decided by its requester, or by one person on two people-decided sides | SQL on `change_requests` joined to `change_request_sides`. The lab keeps `require_distinct_approvers_across_jurisdictions` at its default, `true` |
| SK-5 | No live source or target on a retired account | SQL: `accounts.status = 'RETIRED'` joined to `sources` or `targets` whose state is not `RETIRED` |
| SK-6 | The roles in PostgreSQL match the bindings: none orphaned, none missing | Target admin: the roles under the lab's ligo role prefix compared with `ACTIVE` bindings' users |
| SK-7 | Nothing stays in `PROVISIONING` or `DELETING` longer than 10 minutes. An expired break-glass is reverted within 2 minutes of its expiry | SQL on `bindings.phase` and `updated_at`; SQL on `BREAK_GLASS` change requests past `expires_at` with no `SYSTEM_REVERT` |
| SK-8 | `ligo audit verify` is valid. No password appears in the database or the journals | The CLI as an approver; `serve_scan_secrets`, from `soak.sh`, every 30 minutes and at the end |
| SK-9 | Every outbox event is delivered or abandoned within its retry window, and none is lost | SQL on `notification_outbox`. The receiver's log has every `event_id` marked delivered |
| SK-10 | Both replicas answer, and give the same answer within 30 seconds | The accounts and the bindings, every page, from ligo1 and ligo2 directly: equal after at most 30 seconds of retries. A replica that does not answer for 3 checks in a row, outside a fault, is a violation: a hang is otherwise only a skipped check |

While a fault holds, a check that depends on the faulted component is recorded as skipped, not failed. Its limit counts again from the fault's end.

## 6. Faults

`SOAK_FAULTS=single` runs the catalogue one fault at a time, in seeded order, 5 minutes apart. `all` does the same, then pairs at random. A fault ends at its duration, or at the end of the run. Every fault is undone in a `trap`, even when the run is interrupted.

| Fault | How | Duration | Recovery limit |
| :-- | :-- | :-- | :-- |
| ligo hangs | `systemctl kill -s STOP ligo` on one replica, then `CONT` | 60 s | 60 s; the other replica serves throughout |
| Plugin hangs | `kill -STOP` on one plugin process | 60 s | 2 min |
| PostgreSQL hangs | `kill -STOP` on the postmaster and its backends | 30 s | 2 min |
| Directory hangs | `systemctl kill -s STOP slapd` | 60 s | 2 min after it resumes |
| Slow PostgreSQL | `tc netem` on ligo1 and ligo2, 200 ms ± 50 ms and 1 % loss, filtered to pg's IP | 5 min | 1 min |
| Slow directory | the same, to ldap's IP, 2 s | 5 min | 1 min |
| Slow store | the same, to the store's IP, 500 ms | 5 min | 1 min |
| Partition | `tc netem` with 100 % loss from ligo2 to pg (the VMs have no `nft`): a silent drop, while ligo2 keeps serving | 2 min | 2 min |
| Connections full | idle sessions as a non-ligo role, up to `max_connections` minus the reserved | 2 min | 2 min |
| Long lock | `lock table bindings in exclusive mode` held | 60 s | 2 min |
| Memory pressure | `systemctl set-property ligo MemoryHigh=` on ligo2, at its RSS plus 20 % | 5 min | none: no restart, no error rate above 1 % |
| SPIRE down | SPIRE Server stopped past the workload SVIDs' renewal | 10 min | 2 min after it starts |
| Store sealed | the backend sealed during an apply, then unsealed | 2 min | 2 min |
| Webhook down | the receiver stopped | 5 min | 5 min |
| Reload | `SIGHUP` to one replica | at once | none: no error |
| Maintenance | maintenance on, then off after 2 min | 2 min | 1 min |
| Group change | a person added to or removed from an account's approvers group | at once | the role follows at the session's re-check |
| Rolling restart | `systemctl restart ligo`, one replica, then the other; a replica not listening after 1 min stops the roll, so the other keeps serving (paired with a sealed store, ligo refuses to start until it is unsealed, §8.2 of the main spec) | about 1 min | 1 min each |

`sch_netem` is in the lab VM's kernel. ligo1 and ligo2 are VMs with their own kernels, so `soak.sh` checks for netem there before the first run.

**How a fault runs** (`test/lab/lib/soak-faults.sh`):
1. A marker on ligo1 names the fault. While it exists, the checker still runs the safety checks (SK-4, SK-5, SK-8, SK-9) and records SK-1, SK-2, SK-3, SK-6, SK-7 and SK-10 as skipped. SK-1's limit restarts from the fault's end, and SK-7 is judged again only 10 minutes after the last fault ended.
2. The fault is undone after its duration, then `soak.sh` measures the recovery: the time until both replicas answer an authenticated list. Over the limit is a `RECOVERY` violation. An answer is not enough: `SOAK_FAULT_GAP` (5 minutes) after the fault, every binding that entered `FAILED` or `DELETE_FAILED` since the fault started and is still there is a `DAMAGE` violation, since ligo did not finish the operation by itself.
3. The marker goes when ligo has recovered.
4. No fault starts in the last 15 minutes of the load, so none overlaps the generator's convergence and final check.
5. Every fault in effect is undone by a trap, even when the run is interrupted.

`lab.sh soak fault NAME...|all` applies faults one at a time against the lab a soak run left, without the generator, to try each one on its own.

**Deferred, not in the catalogue:**
- **Disk full.** pg has no volume of its own in the lab, so filling its disk would fill the lab VM's and stop every container.
- **Bad plugin modes.** The soak's bindings use the PostgreSQL and Vault plugins, not the echo plugin, so its modes would not be exercised. A plugin hang (`SIGSTOP`) is covered.
- **A slow webhook receiver.** The receiver has no slow mode; a stopped receiver is covered.

## 7. Builds and drift

- **Race build:** `SOAK_RACE=1` builds `ligo` with `-race`, and so with cgo, for the replicas. Any `WARNING: DATA RACE` in the journals is a `RACE` violation.
- **Connection pool:** `SOAK_MAX_CONNS=2` starves the pools on purpose. The pool deadlock of 7f62dae is that class of bug.
- **Drift:** `soak.sh` samples every 10 minutes into `drift.csv`, one row per host and metric:
  - RSS, threads and open FDs of `ligo`, from `/proc`;
  - the number of plugin processes;
  - PostgreSQL connections per role;
  - the sizes of `audit_log`, `notification_outbox` and `bindings`;
  - the generator's p50 and p95 per hour, from the history.
- **Drift that fails the run:** in a run of 2 hours or more, the last sample of RSS, threads, FDs, plugin processes or connections is more than 20 % over the first hour's median (`DRIFT`). Tables grow with the audit; their growth is reported, not judged.
- **Hang evidence:** ligo has no goroutine endpoint, and adding one would be a product change. So when a request takes over 30 seconds, `soak.sh` keeps that minute's journals and the drift. At the end, before the replicas stop, it sends `SIGQUIT`, and each replica dumps its goroutines to its journal.

## 8. Proving the checker

A quiet night proves nothing unless the checker is shown to catch bugs. `lab.sh soak prove` takes each mutant in turn:
1. applies it to a scratch copy of the tree;
2. builds and deploys that copy;
3. runs 15 minutes with `SOAK_FAULTS=none`, except where noted below;
4. expects the named invariant to trip.

It then runs the unmodified build for 15 minutes, which must trip nothing, and again with `SOAK_MAX_CONNS=1`, which must trip nothing either: otherwise the pool-deadlock mutant's verdict would prove nothing. A ligo that leaves the setup's calls unanswered is an SK-10 violation, since a hang fails there before any check runs. A run that read no credential skips SK-8's password scan rather than failing it.

| Mutant | Bug put back | Must trip |
| :-- | :-- | :-- |
| `pool-deadlock.patch` | The registry listener on the shared app pool, as before 7f62dae; run with `SOAK_MAX_CONNS=1`, so the listener holds the pool's only connection | SK-7 or SK-10 |
| `four-eyes.patch` | One person may approve several sides: the application's check and the database trigger's both removed. The generator's abuse action tries it | SK-4 |
| `revoke-keeps-role.patch` | A revocation that skips dropping the role | SK-1 and SK-6 |
| `cross-tenant-grant.patch` | Every binding's role also granted every tenancy's read role | SK-3 |

A mutant that trips nothing means a gap in the checker. That gap is fixed before any night run.

## 9. Runs

| Run | Settings | Before it |
| :-- | :-- | :-- |
| Shakedown | 2 h, OpenBao, `SOAK_FAULTS=all` | lxd-spiffe 0.4.0 with `keep_alive = true`, a lab rebuild, and a passing `release-run` |
| Night 1 | Vault, `SOAK_RACE=1`, `SOAK_MAX_CONNS=2`, `SOAK_FAULTS=single` | Night-time resources |
| Night 2 | OpenBao, the normal build, `SOAK_FAULTS=all` | Night 1's fixes merged |

**Night-time resources**, set through `lab.local.env` and reverted for daytime work:
- the lab VM: `LAB_LXD_CPUS=12`, `LAB_LXD_MEMORY=48GiB`;
- ligo1 and ligo2: 4 CPUs and 4 GiB each;
- pg: 4 GiB.

**Applying them:** `lab.sh stop`, then `lab.sh start`, with no rebuild. Nothing else runs on the host at night.

**Also during a night, on the host:**
- all 5 fuzz targets, at `nice -n 19`, for the length of the night;
- the load, recorded beside every failure.

**After night 2:**
- **Backup and restore drill:** `pg_dump` of ligo's database, a restore into a new database, and one replica pointed at it. Then every invariant again.
- **Audit tamper:** one `audit_log` row changed as the superuser. `ligo audit verify` must report it.

## 10. Reproducing a failure

`lab.sh soak run` with the same `SOAK_SEED`, on the same commit and settings, draws the same actions and the same faults in the same order. Timing differs, so a race may not repeat. The history therefore records enough to replay the actions around a violation by hand: who did what, to which resource, with which answer. A failure that cannot be reproduced is still reported, with its evidence.

## 11. Pass criteria

A run passes when all of these hold:
- no violation of SK-1 to SK-10;
- no race report;
- no drift that fails the run (§7);
- every fault recovered within its limit, with nobody stepping in;
- every replica's `NRestarts` unchanged, except where a fault itself restarts it.

## 12. Evidence

Each run keeps this in `test/lab/.evidence/soak-<commit>-<label>/`:
- `settings.json` and the seed;
- `history.jsonl` and `drift.csv`;
- `faults.log`;
- each replica's journal;
- the goroutine dumps;
- `versions.txt`;
- `summary.md`: invariants, faults with their recovery times, drift trends and the verdict.

## 13. Not proven even so

- A real production network.
- Real failover of a managed PostgreSQL.
- Clock skew between hosts.
- Load beyond what one lab host can generate.
