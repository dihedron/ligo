# Operating model

## What runs

Each replica runs `ligo serve`, under `ligo.service`, as the user `ligo`. It starts one plugin process per plugin type and zone. Replicas share one PostgreSQL database and hold no state of their own, beyond their stable ID, `LIGO_INSTANCE_ID`.

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
| Platform team | Own `server.yaml` and platforms; confirm targets; can revoke any binding on their platform |
| Additional parties | Such as Information Security: approve the flows the interconnection policy names |
| On call | Break-glass, incidents, this guide |

## A binding's phases

| Phase | Meaning | Workloads get |
| :--------------- | :-------------------------- | :------------------ |
| `PROVISIONING` | A workflow is running | The last good snapshot, if any |
| `ACTIVE` | Fully provisioned | The binding |
| `FAILED` | The last attempt failed terminally | The last good snapshot, if any |
| `DELETING` | Being removed | Nothing |
| `DELETE_FAILED` | Removal failed terminally | Nothing |

Workloads only ever get a binding whose active regex and whose source's current regex both match them, and before its expiry. So a failure never loses working access, and a revocation takes effect at once in the API, even if cleaning up the target takes longer.

## What happens without you

| Loop | Does | Bound by |
| :---------- | :------------------------------------ | :--------------- |
| Sweeper | Starts committed workflows, settles terminated ones, expires requests, reverts break-glass, revokes expired bindings | |
| Reconciler | Reapplies bindings to repair drift, and rotates static secrets when due | `reconciliation.*` |
| Propagator | Applies source and target changes to their bindings, removals of access first | `propagation.*` |
| Dispatcher | Delivers webhooks, for up to 24 h | Each `timeout` |

These run on every replica, coordinated through the database.
