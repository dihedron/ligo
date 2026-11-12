# Blueprint: a single network zone

## Context and assumptions

The smallest production layout. One organisation, one network zone (a data centre segment or one cloud VPC), a handful of application teams, one platform team, one PostgreSQL platform shared by the teams, one Vault or OpenBao. Everybody is reachable from everywhere inside the zone.

It is also the layout to start from: the other blueprints add to it.

## Layout

![A single network zone: one trust domain, one realm, two replicas.](bp-single-network-zone.pdf){width=90%}

| Element | Choice | Chapter |
| :------------------------ | :---------------------------------------------- | :---- |
| Trust domains | One, `corp.internal` | 3 |
| Realms | One, `corp`, also the core realm | 3 |
| SPIRE | One highly available server cluster; one agent on each `ligo` host | 4 |
| Installations | One | 5 |
| Replicas | Two, on hosts that do not fail together, behind a TCP passthrough load balancer | 8 |
| Database | One highly available PostgreSQL, with point-in-time recovery | 8 |
| Store and Transit | One Vault or OpenBao cluster | 2 |

## Jurisdictions

Each team's workloads carry its name in their SPIFFE path, `spiffe://corp.internal/team/<team>/…`, so the team's jurisdiction follows from the path. Workloads and data sit on separate branches; the platform team has a jurisdiction of its own:

| Jurisdiction | Owns | Decided by |
| :------------------------ | :------------------------------ | :------------------------------ |
| `corp/apps/<team>` | The team's sources | The team's leads |
| `corp/data/<team>` | The team's targets on the shared database | The team's leads |
| `corp/platform` | The PostgreSQL platform | The platform team's leads |

Every side needs an approver (`corp/*`), and the only allowed path across jurisdictions is from workloads to data. The configuration, validated by the guide's tests:

```{.yaml include="docs/planning-guide/examples/single-network-zone.yaml" keys="realms authorization charter"}
```

One team's leads decide both sides of a binding between its own workloads and its own data. `require_distinct_approvers_across_jurisdictions` makes that two different people. Where that is not enough, give data its own approvers: a separate group for `corp/data/<team>`.

## Roles

| Activity | Who |
| :---------------------------------------- | :------------------------------------------ |
| `server.yaml`, the platform (four eyes within the team), upgrades | Platform team |
| SPIRE entries for workloads, under `/team/<team>/` | Identity team; teams ask, never create |
| A source, a target, a binding | The team's developers file; two of its leads approve |
| Publishing a target on the shared database | The team files; the platform team approves the platform side |
| Emergency changes | On call, ratified by the team's leads |

## Capacity and availability

Two replicas, default pools, and the sizing method of chapter 8. With one network zone, every part is reachable from both replicas, and the load balancer is the only path workloads need to `ligo`.

## Failure analysis

| Failure | Effect | Mitigation |
| :---------------------------- | :------------------------------------------------ | :---------------------------------- |
| One replica | None visible; its in-flight workflows wait or are recovered | Two replicas; stable IDs |
| PostgreSQL | No changes; reads from cache until `max_staleness` | Database HA |
| Vault or OpenBao | No provisioning; workloads cannot read credentials | Store HA |
| The SPIRE server | None until SVIDs expire | Server HA; SVID lifetimes |
| The zone | Everything | A second site (chapter 8); more network zones: blueprint 10 |

## Variations

- **Static jurisdiction.** If one team owns every workload, `mode: static` with one jurisdiction replaces the path template.
- **Self-service in development.** Leave a development branch out of `required_jurisdictions`; a requester then approves its own side.
- **Automation.** A pipeline with its own review gets `trusted_automation` for its team's jurisdictions, on dedicated runners (chapter 7).

## Checklist

- [ ] SPIFFE path layout agreed with the identity team: `/team/<team>/…`
- [ ] Jurisdiction tree written down: `corp/apps/*`, `corp/data/*`, `corp/platform`
- [ ] Directory groups per team: operators, leads; on call; viewers
- [ ] Two replicas with stable IDs; load balancer in TCP passthrough
- [ ] PostgreSQL HA, PITR, keepalives, connections sized
- [ ] Vault or OpenBao HA; Transit key for `ligo` only
- [ ] SPIRE entries for `ligo` and its plugins, and who updates them on upgrades
