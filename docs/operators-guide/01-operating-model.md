# Operating model

## What runs

Each replica runs `ligo serve`, under `ligo.service`, as the user `ligo`. It runs one plugin process per plugin type and realm that has instances, and starts, reconfigures or stops them as instances change, with no restart. Replicas share one PostgreSQL database and hold no state of their own, beyond their stable ID, `LIGO_INSTANCE_ID`.

| Port | Serves | If it is down |
| :---- | :---------------------- | :-------------------------------- |
| 8443 | Workload API | Workloads keep the credentials they have; they cannot discover new ones |
| 9443 | Admin API and web UI | Nobody can file or approve changes |
| 9090 | Metrics | You are blind, nothing else |

## Who does what

| People | Do |
| :-------------- | :-------------------------------- |
| Source owners | Register sources; file bindings for them |
| Target owners | Publish targets and access levels; approve bindings to them |
| Platform team | Own `server.yaml` (plugin types and their `instance_bounds`); file and approve changes of their platforms and instances; confirm targets; can revoke any binding on their platform |
| Additional parties | Such as Information Security: approve the flows the interconnection policy names |
| Account administrators | Register and retire accounts (`account_admin`); they see no resources and decide nothing |
| Account operators and approvers | Everything above, inside their own account, through their directory groups |
| On call | Break-glass, incidents, this guide |

## Jurisdictions and the charter

A **jurisdiction**, such as `dc/corp-prod` or `cloud/acme/app/payments`, is who decides about a source, a target, a platform or one side of a change. The **charter** is the set of rules every jurisdiction must comply with: how a workload's jurisdiction follows from its SPIFFE path, each jurisdiction's name prefix, which jurisdictions may bind to which and with whose further consent, and how account jurisdictions are formed. There is one charter per installation, in `server.yaml` under `charter:`. Jurisdictions say who decides; the charter says how jurisdictions are formed and how they may deal with each other. Every change request records the charter in force by its hash, and a change decided under a charter that has since changed is refused. Changing it in `server.yaml` raises `CONFIG_CHARTER_CHANGED`.

## A binding's phases

| Phase | Meaning | Workloads get |
| :--------------- | :-------------------------- | :------------------ |
| `PROVISIONING` | A workflow is running | The last good snapshot, if any |
| `ACTIVE` | Fully provisioned | The binding |
| `FAILED` | The last attempt failed terminally; retried by itself if the cause was retryable | The last good snapshot, if any |
| `DELETING` | Being removed | Nothing |
| `DELETE_FAILED` | Removal failed terminally; retried by itself if the cause was retryable | Nothing |

A failure whose cause was retryable, such as a store or SPIRE outage, is retried by the sweeper, as `system:auto-retry`: 15 seconds after it, then up to every minute, until it succeeds. Only a failure its plugin calls final waits for you. A delete removes the access first, the target's role, or the store's leases for dynamic credentials, so an outage of the store cannot keep a revoked binding's access alive.

Workloads only ever get a binding whose active regex and whose source's current regex both match them, and before its expiry. So a failure never loses working access, and a revocation takes effect at once in the API, even if cleaning up the target takes longer.

## What happens without you

| Loop | Does | Bound by |
| :---------- | :------------------------------------ | :--------------- |
| Sweeper | Starts committed workflows, settles terminated ones, expires requests, reverts break-glass, revokes expired bindings | |
| Reconciler | Reapplies bindings to repair drift, and rotates static secrets when due | `reconciliation.*` |
| Propagator | Applies source and target changes to their bindings, removals of access first | `propagation.*` |
| Dispatcher | Delivers webhooks, for up to 24 h | Each `timeout` |

These run on every replica, coordinated through the database.
