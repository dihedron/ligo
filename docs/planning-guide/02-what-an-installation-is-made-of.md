# What an installation is made of

An installation is more than `ligo`. It leans on services that other teams usually run, and a plan must name, for each one, who provides it and what happens when it is missing.

![The parts of an installation, and who talks to whom.](installation.pdf){width=90%}

## The parts

| Part | What `ligo` needs from it | Usually owned by |
| :--------------------- | :---------------------------------------------- | :------------------ |
| `ligo` replicas | Linux hosts (`amd64` or `arm64`); each replica a stable, unique `LIGO_INSTANCE_ID` | Platform team |
| PostgreSQL | One database, reached with `sslmode=verify-full`, four roles; no pooler that hides or reuses `application_name` | Database team |
| SPIRE | One agent per realm on each `ligo` host; entries for `ligo`, its plugins and its workloads | Identity team |
| Vault or OpenBao | A Transit key for sealing; the secret stores where workloads read credentials | Secrets team |
| LDAP directory | Signing people in, and their roles through groups; optional if every administrator uses an SVID | Directory team |
| Load balancer | TCP passthrough to the replicas on 8443 and 9443 | Network team |
| Plugins | Run as processes on each `ligo` host, one per plugin type and realm | Platform team |
| Platforms | The systems that hold targets, such as PostgreSQL databases, reachable from the `ligo` hosts | Their owners |
| Webhook receivers | HTTPS endpoints for change requests and binding events | Whoever acts on them |
| Monitoring and SIEM | Prometheus for metrics; a log pipeline for the audit; optionally an OpenTelemetry collector for traces | Operations, security |

### `ligo` replicas

All replicas of an installation are equal: they serve both APIs, run workflows and take turns on the background loops, coordinated through the database. They keep no state of their own except their ID. A replica that dies must come back under the same `LIGO_INSTANCE_ID`, or its workflows wait until an operator hands them over to another replica.

Each replica starts its plugin processes itself, so a replica host needs everything a plugin needs: the agent sockets of every realm, and network access to the platforms and stores.

### PostgreSQL

The database is the installation. It holds the catalog, the change requests, the audit chain and the workflow journal, in two schemas (`public` and `dbos`) used by four roles with separate rights. The database enforces much of the governance itself, so its integrity is part of the security model, not only its availability.

### SPIRE

`ligo` uses SPIRE three ways: its own identity (the core identity, for serving TLS and for Vault Transit), its plugins' identities, and the trust bundles that verify workloads. Each realm is one agent socket on each `ligo` host. Chapter 4 covers how many servers and agents a plan needs.

### Vault or OpenBao

Two separate uses, which may live in one cluster or two:

- **Sealing.** A Transit key, usable only by `ligo`'s core identity, seals the secrets passed between pipeline stages. No sealing, no provisioning.
- **Secret stores.** Where the store plugin writes each binding's credential and where the workload reads it, with its own JWT-SVID.

### LDAP directory

People sign in to the admin API and web UI with directory credentials, and their roles come from groups. With accounts, one rule maps every account's groups to its roles. Automation signs in with SVIDs and does not need the directory.

### Load balancer

Both listeners need **TCP passthrough**: client certificates must reach `ligo`, which verifies SVIDs itself, and clients verify `ligo`'s own SVID. A load balancer that terminates TLS breaks both. Sessions of the web UI live in the database, so no stickiness is needed.

## When a part is missing

What each outage does, in short; the *Operator's Guide* has the procedures.

| Missing | Workloads | People and automation | Provisioning |
| :----------- | :------------------------------ | :---------------------------- | :---------------------------- |
| One replica | Served by the others | Served by the others | Its in-flight workflows wait for it, or for an operator to hand them over |
| PostgreSQL | Answered from each replica's cache until `max_staleness`, then refused | Admin API errors; unacknowledged decisions must be repeated | Waits, and resumes |
| SPIRE agent on a `ligo` host\* | That replica stops verifying new bundles; once its own SVID expires, it cannot serve TLS | Served by the other replicas | That replica's plugins cannot renew their SVIDs, and fail once they expire |
| Vault or OpenBao | Cannot read credentials from the store | Unaffected | Fails with `SEALED_SECRET_UNAVAILABLE`; a new replica cannot start |
| LDAP directory | Unaffected | No sign-in, no break-glass; a UI session due for its group re-check fails closed until the directory returns | Unaffected |
| A platform | Keep their current credentials | Unaffected | Its bindings fail after retries, and are retried later |
| Load balancer | Cannot reach `ligo`, unless they bypass it | Cannot reach `ligo` | Unaffected |

The PostgreSQL and Vault rows were tested on the lab by stopping the service under bindings in flight (PostgreSQL for 10 seconds). Longer outages have not been tested. \*The SPIRE row follows from how SPIRE issues SVIDs, and has not been tested: plan SVID lifetimes long enough to outlast an agent restart.

## Where this leaves the plan

Every part in the first table has an owner outside the platform team, except `ligo` and its plugins. Before Part II, list the teams that own each part in your organisation: chapter 7 builds the responsibilities on that list, and chapter 8 builds availability on what each team can promise.
