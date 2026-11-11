# Durability and sealing

## Durable workflows

Provisioning spans systems with no shared transaction, and a process can die at any point. Workflows run on DBOS, which checkpoints each step's result in PostgreSQL. After a crash, a replica resumes its pending workflows from their last checkpoint.

**A workflow's start is transactional.** The change request's application, the binding's revision and the workflow ID commit together, and the sweeper starts any committed workflow that did not start. So a crash between commit and start loses nothing.

**Fencing.** A workflow ID is unique per binding, revision and attempt, and a step records its work only if the binding still names that workflow. So a stale attempt cannot overwrite a newer one.

**A replica keeps its executor ID.** DBOS recovers only workflows pending under a replica's own ID, so a replica must come back under the same ID. For a replica gone for good, an operator re-enqueues its workflows. `ligo` refuses while such a replica still has database sessions, but that is evidence, not proof: one that only lost its database connection still runs, so the operator must confirm the host is down.

## Sealing secrets between stages

A password made in Stage 2 must reach Stage 3, and checkpoints are written to the database. Sealing keeps it out of the database in clear, whatever happens:

1. The step generates a data key, encrypts the secret with AES-GCM, and wraps the key with Vault Transit.
2. The wrapped key is bound into the encryption's associated data, along with the binding, revision, attempt and stage. A blob cannot be moved to another context.
3. Only the sealed form is checkpointed.

The Transit key can be used only by `ligo`, and cannot be exported. Sealed blobs live only as long as workflow retention.

**If Transit is unavailable**, the attempt fails terminally with `SEALED_SECRET_UNAVAILABLE`. A retry is a new attempt, which rotates: it does not need the lost secret.

## Zero-downtime updates

`bindings` holds the desired revision and an **active snapshot** of the last that fully succeeded. The resolver serves only the snapshot. So while an update applies, workloads see the old state, and on failure they keep it. The accepted limit is that a platform can partly converge towards a new revision while workloads are told the old one.

## The audit log

Each entry hashes the previous one. The application can only insert: it has no update or delete privilege, and a trigger refuses even the owner. Entries are written in the same transaction as what they record, with a lock order that makes the chain linear.

A hash chain alone does not stop someone with write access to the database: they can change an entry and recompute every hash after it. So `ligo` regularly signs the head of the chain with an ed25519 key in Transit, outside the database, and stores these **checkpoints** in a table of their own, append-only too. A rewritten chain no longer matches its signed checkpoints.

Checkpoints also keep verification cheap. One replica verifies every 10 minutes from the newest checkpoint, in short batches, and the whole chain daily; the result is a metric. An edit before the newest checkpoint that did not recompute hashes is found by the daily full pass. Checkpoints have no foreign key to the entries, so they anchor a log whose oldest entries were pruned.

The log is pruned only if a retention is set, and only through a checkpoint that an operator has exported. `ligo audit export` writes the chain to a file, with the checkpoints and the public keys, verifies it and records it; the file verifies later without `ligo`. Once a day the verifying replica deletes the exported entries older than the retention, through the newest checkpoint that qualifies, which stays as the anchor of what remains. The application still has no delete privilege: deletion goes through one database function, owned by the migrator, that refuses anything but an exported checkpoint signed over a day ago.

## Notifications

A transactional outbox: the row commits with the event, so an event is never lost and never announced unless it committed. A webhook failure never delays the change. Delivery is at least once, signed with HMAC, retried and abandoned after 24 hours. Delivered rows go after a day by default, abandoned ones after 30 days; both are settings.

## High availability

Replicas are equal. Singletons, such as the sweeper's work, are coordinated with PostgreSQL advisory locks. Maintenance mode is one transactionally checked setting, so no workflow can start after it commits, and no replica can miss it.

The lab has shown each of these on real services: concurrent approvals on two replicas applied once, a replica killed mid-workflow resuming, a frozen replica's work recovered by another, and PostgreSQL stopped under bindings in flight.
