# Incident procedures

## Break-glass: an emergency change

People in a `break_glass` group for every side that would otherwise need a decision can apply a change at once:

```bash
ligo break-glass apply -f binding.yaml --justification "..." --incident INC0012345 --ttl 1h
ligo break-glass delete <name> -r <revision> --justification "..." --incident INC0012345
ligo break-glass list --open
```

They sign in again with their password, and their LDAP groups are read afresh, so a stolen session is not enough. An SVID cannot use it.

- A `CREATE` or `UPDATE` **reverts automatically** at its TTL, unless an approver of each side, a different person, ratifies it first: `ligo cr ratify <id> --side TARGET --comment "..."`. Ratifying takes a person; an SVID approver gets `403`.
- To end it early: `ligo cr revert <id> --comment "..."`.
- A `DELETE` is **never reverted**, as restoring access could re-grant it to a compromised workload. It still needs a review.

If a revert fails, the emergency state stays served until you retry it: `BREAK_GLASS_REVERT_FAILED` must page someone.

## A compromised workload

1. Revoke it: `ligo break-glass delete <name> ...`, or with one owner's approval through `ligo delete`. To contain a whole source or jurisdiction on a target, use `ligo target revoke-bindings`.
2. The API stops serving it at once. The workflow then removes its credential and role, and ends the role's sessions on PostgreSQL.
3. Check it reached the end: `ligo get binding <name>` answers `404`, and the audit shows `DELETE_COMPLETED`.
4. If you need the workload's SPIRE entry gone too, that is SPIRE's: `ligo` does not manage it.

## A plugin or platform is down

Workloads keep the last good snapshot. Retryable errors are retried within the step, up to `plugins.retry`, then the binding is `FAILED`, and retried by itself every minute or so until the platform is back; propagations resume by themselves too. `ligo retry <binding>` starts one at once. A plugin process that dies is restarted, with a back-off.

## Vault or OpenBao is down

`ligo` cannot seal secrets: an attempt that needs to fails with `SEALED_SECRET_UNAVAILABLE`. A new replica cannot start, and logs the reason; running replicas keep serving. Workloads cannot read credentials from the store until it is back. Unseal it: the bindings that failed meanwhile are retried by themselves within a minute or so, each a new attempt, which rotates. Revocations are not held up by it: a delete removes the target's role before it cleans the store.

This was tested by stopping both backends under real bindings.

## PostgreSQL is down

The admin API answers errors, and replicas keep running. The workload API answers from its cache until `max_staleness`, then refuses rather than answer from old data. In-flight workflows wait and resume when the database returns. Approvals and other changes must be repeated if they were not acknowledged.

This was tested by stopping PostgreSQL for 10 s under bindings in flight: every binding converged, and no replica restarted. Longer outages have not been tested.

## A replica died

Start it again under the **same** `LIGO_INSTANCE_ID`: its workflows resume from their last checkpoint. Until then, only its bindings stay `PROVISIONING` or `DELETING`, while resolution keeps serving their last state.

If it cannot come back:

1. **Confirm that the host is down.** The check on live sessions is evidence, not proof: a replica that lost only its database connection still runs, and a plugin call could overlap the second run.
2. `ligo executors list` shows each executor's pending workflows and live sessions.
3. `ligo executors recover <id>` re-enqueues them for any replica of the same version. It refuses a live executor (`409 executor-alive`) and the replica you asked (`409 executor-self`), with no force option. Workflows of other versions stay put and are counted.

## Restoring from a backup

1. Restore `public` and `dbos` together.
2. Start `ligo` with `--maintenance`.
3. `ligo maintenance status --wait-drained`, so that the sweeper settles the bindings.
4. While still in maintenance, `UPDATE bindings SET last_rotated_at = NULL`, so that every static secret is due for rotation: sealed checkpoints may be stale, and secrets may have been issued after the backup point.
5. `ligo maintenance off`. The next reconcile run rotates them.

## The audit chain does not verify

`ligo_audit_chain_valid` is 0, or `ligo audit verify` reports `valid: false`. Someone with database rights has altered history, or a backup was restored badly. Treat it as a security incident:

1. Preserve the database: take a copy before anything else writes to it.
2. Run `ligo audit verify --full` and note the first broken `id`. A break at a checkpoint means the entries up to it were rewritten and their hashes recomputed: whoever did it had the database but not the signing key. A break between checkpoints, found only by `--full`, means an entry was edited in place.
3. Compare the entries from the broken `id` onwards with your SIEM's forwarded copy.
4. Look at who holds `ligo_migrator` and the superuser, and at the database's own logs.

Before treating a missing range of entries as tampering, look for a `SYSTEM_AUDIT_PRUNED` entry: a prune deletes the oldest entries on purpose, and names the checkpoint it stopped at. The oldest entry left must then chain onto that checkpoint, which `ligo audit verify --full` checks.

If `ligo audit verify` answers `503 unavailable` instead, the chain is not broken: `ligo` cannot reach the `ligo-audit` key. Check Vault or OpenBao and the `ligo-sealer` policy.

## An instance is quarantined

`ligo_instance_drift{kind,name}` is 1, the log says `instance quarantined: its row does not verify`, and the audit holds `SYSTEM_INSTANCE_DRIFT`. The row of that platform or instance was changed in the database outside `ligo`: its hash or its signature by the audit key does not match. `ligo` no longer configures or offers it, and bindings on it cannot be provisioned. Treat it as a security incident.

1. Find who wrote to the database, as for an audit chain that does not verify.
2. Compare the row with the instance's audit (`ligo audit list platform NAME`) and its last applied change request.
3. File the intended definition again (`ligo apply`, with `expectedRevision` the row's revision), and have it approved: the new, signed row ends the quarantine and the metric returns to 0.

## A trust bundle conflict

`ligo` fails closed on bundle errors: the workload API answers `503`. See *Troubleshooting*.
