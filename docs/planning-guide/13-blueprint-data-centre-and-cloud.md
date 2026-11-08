# Blueprint: a traditional data centre interconnected with a multitenant cloud

## Context and assumptions

The traditional data centre of blueprint 10 and the multitenant cloud of blueprint 12 belong to one organisation and must now work together, in both directions: cloud accounts need data-centre databases (the order history lives there), and data-centre applications need tenancies in the cloud (new services are built there). Each side keeps its own teams, its own SPIRE and its own `ligo`; neither will hand its administration to the other. Information Security consents to everything that crosses.

## Layout

::: landscape

![A data centre and a multitenant cloud, each with its own installation, trusting each other by federation.](bp-data-centre-and-cloud.pdf){width=100%}

:::

| Element | Choice | Chapter |
| :------------------------------ | :---------------------------------------------- | :---- |
| Trust domains | Unchanged: `prod.dc.internal`, `test.dc.internal`; `cloud.internal` | 3 |
| Installations | Two, unchanged in shape: the data centre's and the cloud's | 5 |
| Cloud workloads, verified by the data centre | Federated: the data centre's SPIRE federates with the cloud's, `via_realm: prod` | 3, 4 |
| Data-centre workloads, verified by the cloud | Federated: the cloud's SPIRE federates with the data centre's, `via_realm: cloud` | 3, 4 |
| Credentials across | Each production store's JWT authentication also trusts the other side's domain | 3 |
| Test | Never crosses: `test.dc.internal` is federated with nobody | 3 |

Each installation decides for itself whom it trusts: federation is configured by the side that verifies. Neither side can make the other accept its workloads.

## Which side decides

A binding lives in the installation that holds its target. So the target's side always runs it:

| A binding from | To | Lives in | Consent |
| :------------------------------ | :------------------------------ | :---------------------------- | :------------------------------------------ |
| A cloud account's project | A data-centre database | The data centre's installation | The account's approver, the data's leads, Information Security |
| A data-centre core application | A cloud tenancy | The cloud's installation | The application's leads, the tenancy's account (or the platform approver), Information Security |
| The data centre's DMZ | A cloud tenancy | Nowhere: no rule allows it | |
| Test, either side | Anything across | Nowhere: not federated | |

### In the data centre's installation

The data centre registers the cloud accounts it lets in, as the regulated zone does in blueprint 12: registering an account there is the gate. The cloud's account structure is repeated in its charter, and the accounts' approvers come from groups the data centre's directory holds for them.

```{.yaml include="docs/planning-guide/examples/interconnect-data-centre.yaml" keys="charter"}
```

### In the cloud's installation

The cloud accepts data-centre workloads by their SPIFFE paths, with the data centre's own jurisdictions (`dc/prod/core/<team>`), and only from the core: the DMZ has no rule, so it is denied by default. The data-centre teams that file and approve there need identities in the cloud's directory.

```{.yaml include="docs/planning-guide/examples/interconnect-cloud.yaml" keys="charter"}
```

## People in two directories

Each installation signs people in against one directory. Where the data centre and the cloud keep separate directories, the people who decide on the other side need an identity there: the data centre's application leads in the cloud's directory, the cloud accounts' approvers in the data centre's. Plan who creates and removes those identities, as part of onboarding an account or a team, or give both installations one corporate directory, which removes the mirroring altogether.

## Roles

| Activity | Who |
| :---------------------------------------- | :------------------------------------------ |
| Federation, each way | The verifying side's identity team, with Information Security |
| Letting a cloud account into the data centre | The data centre's account administrators, after Information Security agrees |
| Letting a data-centre team into the cloud | The cloud's platform team: grants for that team's jurisdictions |
| Approving a crossing binding | Both sides' approvers and Information Security |
| Revoking it | Either side's owner alone, at once |
| Mirrored identities | Both directory teams, in the onboarding and offboarding procedures |

## Capacity and availability

Each installation as before. A crossing binding depends on both sides' SPIRE (the bundle is federated, the SVIDs are the workload's own), on the target side's store and on the network path between the zones; the flows of each binding (`GET /v1/flows`) list what the firewalls between them must open.

## Failure analysis

| Failure | Effect | Mitigation |
| :---------------------------- | :------------------------------------------------ | :---------------------------------- |
| Federation stops one way | The verifying side keeps the last bundle; after the other side rotates its CA, its workloads are refused there | Federation monitored on both sides |
| The cloud installation is down | Data-centre workloads cannot discover cloud bindings; existing credentials work | Its own HA and failover |
| The data centre's installation is down | Cloud workloads cannot discover data-centre bindings; existing credentials work | Its own HA |
| A compromised cloud account | Reaches only the data-centre data that Information Security approved for it | Revoke from either side; retire its sources in the data centre, then its registration |
| A mirrored identity left behind | A person who left one side still decides on the other | Offboarding removes both; one directory avoids it |

## Variations

- **One installation for both**, if one platform team can run both sides and the data centre accepts it: the realms of blueprint 10 plus the cloud's, one charter, and no federation inside `ligo` (each trust domain a realm). Chapter 5's criteria decide.
- **One direction only**, if the data centre must never depend on the cloud: no federation from the data centre to the cloud.
- **The regulated zone of blueprint 12 alongside**: a third installation, federating with whichever side it lets in.

## Checklist

- [ ] Federation, each way, configured by the verifying side, with Information Security
- [ ] Each production store trusting the other side's JWT-SVIDs; test stores trusting nobody across
- [ ] The cloud accounts admitted to the data centre, and who admits them
- [ ] The data-centre teams granted in the cloud, core only
- [ ] Interconnection rules with Information Security as a party, both sides
- [ ] Mirrored identities in onboarding and offboarding, or one directory
- [ ] Firewall rules between the zones driven by each binding's flows
