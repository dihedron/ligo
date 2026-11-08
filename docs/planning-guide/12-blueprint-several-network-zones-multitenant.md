# Blueprint: a multitenant cloud over several network zones

## Context and assumptions

The cloud of blueprint 11 grows: it now runs in two regions, `eu-1` and `eu-2`, both administered by the same identity and platform teams, and it gains a regulated zone for risk data, which a regulator requires to be administered separately: its own SPIRE, its own database, its own platform team. Some cloud accounts may reach regulated data, with Compliance's consent; most may not.

## Layout

::: landscape

![A multitenant cloud over two regions, and a regulated zone with its own installation.](bp-several-network-zones.pdf){width=100%}

:::

The two regions and the regulated zone are three network zones, but the decisions differ:

| Question | Regions `eu-1` and `eu-2` | Regulated zone |
| :------------------------------------ | :-------------------------------- | :-------------------------------- |
| Trust domain (chapter 3) | One, `cloud.internal`: same administrators | Its own, `regulated.internal`: different administrators |
| SPIRE (chapter 4) | One upstream server; a nested downstream server per region | Its own HA cluster, federating with the cloud |
| Installation (chapter 5) | One: same teams, same rules | Its own: the regulator forbids shared administration |
| `ligo` replicas (chapter 8) | In `eu-1`, with the database primary; `eu-2` is the failover site | In the regulated zone |

The cloud installation is blueprint 11's, unchanged. The regulated installation holds one realm, `reg`, and verifies cloud workloads through federation (topology C): the regulated SPIRE server federates with the cloud's, so the higher-assurance side decides what it trusts.

## Jurisdictions

In the regulated installation, cloud accounts appear with the same jurisdictions as in the cloud, `cloud/<account>/app/<project>`, and the same directory groups decide for them. But only the accounts registered **in the regulated installation** can register sources there: registering an account there is the gate, held by the regulated zone's own account administrators.

| Jurisdiction | Owns | Decided by |
| :------------------------------ | :------------------------------------ | :---------------------------- |
| `reg/apps/<team>` | Regulated workloads | The team's leads |
| `reg/data/<team>` | Regulated data | The team's leads |
| `reg/dba` | The regulated database platform | The regulated DBA leads |
| `cloud/<account>/app/<project>` | A cloud account's sources, here | The account's approvers |
| `sec/compliance` | Nothing; approves as a party | Compliance |

```{.yaml include="docs/planning-guide/examples/regulated-zone.yaml" keys="realms server charter"}
```

A binding from a cloud account to regulated data therefore needs three consents: the account's approver, the regulated team's leads, and Compliance. Either the account or the regulated team can revoke it alone.

## What crosses the boundary

| Crossing | Answer |
| :---------------------------------------- | :------------------------------------------------ |
| Cloud workloads calling the regulated `ligo` | Verified with the cloud bundle, federated in; the regulated `ligo` serves a corporate CA certificate, so cloud workloads need no regulated bundle |
| Cloud workloads reading regulated credentials | The regulated store's JWT authentication trusts `cloud.internal` too, configured by the regulated secrets team |
| Cloud workloads reaching regulated databases | Firewall rules per binding's flows (`GET /v1/flows`), opened by the regulated network team |
| People | One directory; separate groups for the regulated installation's roles |

A cloud workload with bindings in both installations asks both for its bindings: each installation is a separate API.

## Roles

| Activity | Cloud installation | Regulated installation |
| :---------------------------------------- | :------------------------ | :------------------------ |
| `server.yaml`, platforms, policy | Cloud platform team | Regulated platform team |
| Registering accounts | Cloud account administrators | Regulated account administrators: the gate |
| SPIRE | Cloud identity team | Regulated identity team, deciding the federation |
| Database, store, Transit key | Cloud teams | Regulated teams, nothing shared |
| Approving cloud-to-regulated bindings | | Account approvers, regulated leads, Compliance |

## Capacity and availability

Each installation is sized on its own (chapter 8). The cloud installation's replicas run in `eu-1`, beside the database primary; workloads in `eu-2` reach them across regions, at discovery only, since credentials come from the store and data from the targets. `eu-2` holds the database replica and stopped replicas for failover. Running replicas in `eu-2` too, writing across regions to the `eu-1` primary, would serve `eu-2`'s reads locally; it has not been tested.

## Failure analysis

| Failure | Effect | Mitigation |
| :---------------------------- | :------------------------------------------------ | :---------------------------------- |
| Region `eu-1` | The cloud installation stops until failover to `eu-2` | Rehearsed failover (chapter 8) |
| The cloud SPIRE upstream | Downstream servers keep issuing until their own certificates expire | Upstream HA |
| The federation link | The regulated `ligo` keeps the last cloud bundle; a rotated cloud CA is refused until it returns | Monitoring of the federation |
| A compromised cloud account | Reaches only regulated data three parties approved | Revoke from either side, at once |
| The regulated installation | Regulated bindings only; the cloud is unaffected | Its own HA |

## Variations

- **Separate trust domains per region**, if each region has its own identity team: two realms in the cloud installation (topology A).
- **One installation for everything**, if the regulator accepts shared administration: the regulated zone becomes a realm and a branch of jurisdictions, and the interconnection policy keeps Compliance as a party.
- **No federation**: regulated data reachable only from regulated workloads, and the cloud accounts never registered there.

## Checklist

- [ ] One trust domain per administering team, not per region
- [ ] Nested SPIRE per region under one upstream; regulated SPIRE separate
- [ ] Federation configured on the regulated side; `federatesWith` on the regulated `ligo`'s entry
- [ ] The regulated store's JWT authentication trusting `cloud.internal`
- [ ] Accounts registered in the regulated installation only with Compliance's agreement
- [ ] Interconnection: cloud to regulated data with Compliance as a party
- [ ] Failover of the cloud installation to `eu-2` rehearsed
