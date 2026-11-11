# Capacity, availability and recovery

## The question

How many replicas, how big a database, what must PostgreSQL, Vault or OpenBao, the directory and SPIRE promise, and how does the installation come back after losing a host, a database or a site?

No capacity figure in this chapter comes from a measurement yet: the overnight soak planned for this release will give the first ones, and a later edition will add them with where they were measured. Until then, the chapter gives the method.

## Replicas

| Decision | Recommendation | Why |
| :------------------------------ | :------------------------------------------------ | :---------------------------------- |
| How many | At least two, on hosts that do not fail together | Every replica serves both APIs and takes turns on the background work; one survives the other |
| Identity | A stable `LIGO_INSTANCE_ID` per replica, never reused by another | A replica that dies resumes its workflows only under its own ID |
| Placement | Each replica needs every realm's agent socket, and reach to every platform and store | Each replica starts its own plugin processes |
| Load balancer | TCP passthrough on 8443 and 9443, health checked per replica | `ligo` verifies client SVIDs itself |

Two replicas, with one stopped, frozen or killed under load, have been tested on the lab, with a load balancer in front; more have not.

A replica that will not come back is replaced by recovering its workflows on another replica, after confirming that its host is down: `ligo executors recover` refuses while the old replica still holds a database session.

Workload reads are answered from each replica's in-memory cache, so they scale with replicas and barely touch the database. Two things are per replica, not per installation: the resolution cache, and the rate limits. With *N* replicas, a client can fail *N* times as many logins before being slowed; the directory's own lockout policy is the bound across the installation.

## PostgreSQL

The database is the installation (chapter 2). Give it the availability you expect of `ligo`.

**Connections.** Each replica opens two pools of up to `storage.postgres.max_conns` each (application and reader), the workflow engine's own pool, and a few connections of its own: one for each listener that follows changes, and one at a time for each background loop's lock. Size `max_connections` on the server for all replicas at once, with room for administration, and check the plan against `pg_stat_activity`, grouped by `application_name`, on a test installation. Small pools on hosts with few CPUs were the cause of a hang found on the lab before this release; it is fixed, but keep pools no smaller than the defaults.

**Requirements:**

- TLS with `verify-full`.
- No pooler that hides or reuses `application_name`: recovering a replica relies on it.
- TCP keepalives on the server short enough to end a dead host's sessions in minutes, not the Linux default of about two hours: `tcp_keepalives_idle` 60, `tcp_keepalives_interval` 10, `tcp_keepalives_count` 6.
- High availability by the database team's usual means, such as Patroni, with one primary that every replica writes to.

**Growth.** Finished workflows are deleted after `storage.dbos.workflow_retention`, delivered webhooks after `notifications.delivered_retention` (24 hours by default), and abandoned ones after `notifications.abandoned_retention` (30 days). The audit log grows with every change, about 35,000 entries in a busy night. It is kept whole unless you set `storage.audit.retention`; then entries older than that are deleted once a day, but only those an operator has exported with `ligo audit export`. Plan its storage and its size in backups for the retention you choose, and storage for the exported files, which are the archive. The SIEM's forwarded copy is the long-term record.

**Backups.** The schemas `public` and `dbos` live in the same database and must be backed up together, with point-in-time recovery. After a restore, `ligo` starts in maintenance mode, settles in-flight bindings, and rotates every static secret, because secrets may have been issued after the backup point (*Operator's Guide*, "Restoring from a backup").

## Vault or OpenBao

| Use | If it is down |
| :---------------------- | :------------------------------------------------------------ |
| Transit, for sealing | Provisioning fails; a replica cannot start; running replicas keep serving |
| Secret stores | Workloads cannot read credentials, even for bindings that work |

The stores are on the workloads' critical path, Transit only on `ligo`'s. Plan the stores' availability like any service workloads depend on, and keep the Transit key non-exportable, available to `ligo`'s core identity alone.

## Directory and SPIRE

The directory is needed to sign in and for break-glass, which reads groups afresh; automation with SVIDs does not need it. Make it at least as available as the break-glass path must be.

SPIRE is needed by `ligo`, its plugins and every workload. Its availability is chapter 4's: highly available servers, and SVID lifetimes longer than the outages you plan for.

## Failure domains

| What fails | What stops | What keeps working |
| :------------------------ | :-------------------------------------- | :-------------------------------------- |
| One replica's host | Its in-flight workflows, until recovered | Everything else, through the other replicas |
| The database | Changes; reads after `max_staleness` | Reads from cache until `max_staleness`; workloads' existing credentials |
| Vault or OpenBao | Provisioning; workloads reading credentials | Workloads holding credentials; changes that need no sealing; removing access on the targets |
| The directory | People signing in; break-glass | Automation; workloads |
| A SPIRE server | New and renewed SVIDs, after their lifetime: JWT-SVIDs often last only minutes, and the plugins need them for Vault | Everything, until SVIDs expire; plugins keep their last bootstrap credential |
| A site | Everything placed only there | What has a copy elsewhere (below) |

When the failed dependency returns, `ligo` finishes on its own what the outage interrupted: a binding whose attempt failed on a retryable cause is retried every minute or so until it succeeds. No one has to retry them by hand, and a revocation interrupted by an outage of the store or SPIRE completes once it is over. Plan for the length of an outage, not for its clean-up.

## Several sites

`ligo` runs active in one place at a time: every replica writes to one PostgreSQL primary. A second site can take over, with the database replicated to it. `ligo` gives these elements; for the replication itself, follow the PostgreSQL documentation and your HA product's.

- **Which replicas run.** Run replicas only at the site with the primary; start the second site's replicas after failover. Give them their own `LIGO_INSTANCE_ID`s, and recover the lost site's workflows to them with `ligo executors recover`, once that site is confirmed down.
- **Asynchronous replication loses the last transactions.** The audit chain stays valid, as it lives in the same database, but ends earlier than before; the SIEM may hold entries the database lost. Decisions people made in the lost interval must be made again. Treat a failover with possible loss like a restore: maintenance mode, settle, rotate static secrets.
- **Synchronous replication** avoids the loss, at the cost of write latency on every change.
- **The Transit key must exist at both sites**, by Vault's or OpenBao's own replication: in-flight workflows carry secrets sealed with it.
- **Each site needs** SPIRE agents for every realm on its `ligo` hosts, reach to every platform, and a load balancer address workloads can find.

None of this has been tested on the lab yet.

## Sizing method

Until measured figures exist:

1. Count sources, targets and bindings per installation, and changes per day.
2. Start with two replicas and the default pools; size PostgreSQL's connections as above.
3. Load a test installation with that volume, and watch `ligo_workflow_duration_seconds`, `ligo_propagation_oldest_seconds`, `ligo_resolution_cache_age_seconds` and the database's connections and CPU.
4. Add replicas for workload read load, and database resources for change load.

## Recommendation

- Two replicas or more, in separate failure domains, behind a TCP passthrough load balancer.
- PostgreSQL highly available, with point-in-time recovery, short TCP keepalives, and connections sized for all replicas.
- Secret stores as available as the workloads that read them; Transit as available as provisioning must be.
- A second site only with a rehearsed failover, and a decision, written down, between losing recent decisions and paying for synchronous writes.

## When this goes wrong

| Mistake | Consequence |
| :---------------------------------------- | :------------------------------------------------- |
| One replica | Its host's outage stops changes and reads |
| A replica restarted under a new ID | Its old workflows wait until recovered by hand |
| A pooler that rewrites `application_name` | Recovery cannot tell a live replica from a dead one |
| Default TCP keepalives | A powered-off host blocks its recovery for about two hours |
| Backing up `public` without `dbos` | A restore loses or repeats workflows |
| Replicas running at both sites against two primaries | Two installations diverge, each with its own audit |
