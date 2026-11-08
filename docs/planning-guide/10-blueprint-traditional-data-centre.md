# Blueprint: a traditional data centre

## Context and assumptions

An on-premises data centre with three network zones: the production core, a DMZ facing the internet, and test. Classic teams: a DBA team runs the databases, application teams own their workloads and data, Information Security approves what crosses from the DMZ, and changes to production follow an ITSM change process. No tenants: the organisation is one, so there are no accounts.

## Layout

::: landscape

![A traditional data centre: three network zones, two trust domains, one installation.](bp-traditional-data-centre.pdf){width=100%}

:::

The three network zones do not become three trust domains. Production core and DMZ are administered by the same operations team, so they share `prod.dc.internal`; the DMZ is told apart by the SPIFFE path, and so by its jurisdiction. Test gets its own domain, `test.dc.internal`, so that test administrators cannot issue production identities.

| Element | Choice | Chapter |
| :------------------------ | :---------------------------------------------- | :---- |
| Trust domains | `prod.dc.internal` (core and DMZ), `test.dc.internal` | 3 |
| Realms | Both (topology A): `ligo` provisions databases in each; `prod` is the core realm | 3 |
| SPIRE | One HA server cluster per domain; two agents on each `ligo` host | 4 |
| Installations | One, in the production core's management segment, reaching the test databases through the firewall | 5 |
| Workload listener | A corporate CA certificate (`tls_source: file`), so test workloads need no production bundle | 3 |
| Admin SVIDs | Accepted from `prod.dc.internal` only | 4 |
| Stores | One Vault or OpenBao per domain, each trusting its own workloads' JWT-SVIDs | 3 |

## Jurisdictions

Production workloads carry their segment and team in the path, `spiffe://prod.dc.internal/seg/<core|dmz>/team/<team>/…`. Test workloads all belong to one jurisdiction.

| Jurisdiction | Owns | Decided by |
| :------------------------ | :------------------------------ | :------------------------------ |
| `dc/prod/core/<team>` | The team's production workloads | The team's leads |
| `dc/prod/dmz/<team>` | The team's workloads in the DMZ | The team's leads |
| `dc/prod/data/<team>` | The team's production data | The team's leads, or change automation |
| `dc/prod/dba`, `dc/test/dba` | The database platforms | The DBA team's leads |
| `dc/test/apps`, `dc/test/data/*` | Test workloads and data | Self-service |
| `sec/infosec` | Nothing; approves as a party | Information Security |

The interconnection policy denies test to production and back first, then allows core to data, DMZ to data with Information Security as an additional party, and test to test:

```{.yaml include="docs/planning-guide/examples/traditional-data-centre.yaml" keys="realms charter"}
```

## Roles

The ITSM change process stays the approval of record for production data: change automation, running on dedicated AWX nodes, holds `trusted_automation` on `dc/prod/data/*` and cites the approved change (`CHG…`). It decides only the data side; the workload side of a binding is still decided by its own leads.

```{.yaml include="docs/planning-guide/examples/traditional-data-centre.yaml" keys="authorization"}
```

| Activity | Who |
| :---------------------------------------- | :------------------------------------------ |
| `server.yaml`, realms, the interconnection policy | Platform team, with Information Security consulted |
| Database platforms, publishing targets | DBA team |
| SPIRE entries, including `seg/dmz` paths | Identity team, for both domains |
| A binding from the core | The team files; its leads approve both sides, or the change automation the data side |
| A binding from the DMZ | As from the core, plus Information Security |
| Test | Developers, without approval |
| Emergency changes in production | On call, ratified by the team's leads |

## Capacity and availability

As blueprint 9, plus: the `ligo` hosts need reach into the test zone (PostgreSQL and Vault of test, and the test SPIRE servers), and each host runs two agents. The DMZ's workloads need reach to the load balancer, the production Vault and their databases, which the flows (`GET /v1/flows`) list for each one.

## Failure analysis

| Failure | Effect | Mitigation |
| :---------------------------- | :------------------------------------------------ | :---------------------------------- |
| The test SPIRE server | Test plugins and workloads lose SVIDs when they expire; production unaffected | Its own HA, at test's level |
| The firewall to test | Test bindings fail after retries; production unaffected | None needed beyond retry |
| A compromised DMZ workload | Reaches only data whose binding Information Security approved | Revoke at once: either owner alone |
| A compromised test administrator | Can issue test identities only | Separate trust domain |

## Variations

- **A separate installation for test**, inside the test zone, if central hosts must not reach it (chapter 5). Production then needs one realm only.
- **The DMZ as its own trust domain**, if a different team administers its identities. It becomes a third realm, or a federated domain if `ligo` provisions nothing in it.
- **No change automation**: the data side is decided by the team's leads.

## Checklist

- [ ] Trust domains per administering team, not per network zone
- [ ] SPIFFE path layout for production: `/seg/<core|dmz>/team/<team>/…`
- [ ] Interconnection denials first; Information Security on DMZ-to-data
- [ ] Two agents on each `ligo` host; firewall from the hosts into test
- [ ] Workload listener certificate from the corporate CA
- [ ] Admin SVIDs only from production
- [ ] AWX on dedicated nodes, with its own SPIFFE ID; change references in `CHG` form
- [ ] One store per domain, each trusting its own workloads
