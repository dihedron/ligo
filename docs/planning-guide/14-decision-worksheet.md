```{=latex}
\appendix
```

# Decision worksheet

Fill it in while reading Part II, one copy per installation. Each answer should name who decided it and when.

## Trust domains and realms (chapter 3)

| Question | Answer | Chapter |
| :-------------------------------------------------------- | :-------------------------------- | :---- |
| Which network zones exist, and who administers each? | | 3 |
| Which trust domains, one per administering team? | | 3 |
| Which are realms of this installation, and which federated? | | 3 |
| Which realm is the core realm? | | 3 |
| Does every store trust the trust domains of the sources it serves? | | 3 |
| Can every network zone reach `ligo`, its store and its targets? | | 3 |

## SPIRE (chapter 4)

| Question | Answer | Chapter |
| :-------------------------------------------------------- | :-------------------------------- | :---- |
| How many SPIRE server clusters, and how highly available? | | 4 |
| Which agents run on each `ligo` host? | | 4 |
| Who creates `ligo`'s and its plugins' entries, and updates them on upgrades? | | 4 |
| Who creates workloads' entries, and can tenants influence it? | | 4 |
| From which trust domain are admin SVIDs accepted? | | 4 |

## Installations (chapter 5)

| Question | Answer | Chapter |
| :-------------------------------------------------------- | :-------------------------------- | :---- |
| One installation, or several? Which boundary justifies each extra one? | | 5 |
| Which jurisdictions and trust domains does each installation serve? | | 5 |
| What do installations share (database cluster, Vault, SPIRE, directory)? | | 5 |

## Jurisdictions and the charter (chapter 6)

| Question | Answer | Chapter |
| :-------------------------------------------------------- | :-------------------------------- | :---- |
| What is the jurisdiction tree? | | 6 |
| What SPIFFE path layout carries each workload's jurisdiction? | | 6 |
| Which jurisdictions require an approver? | | 6 |
| Which pairs of jurisdictions may bind, and with which parties? | | 6 |
| Are there accounts? Their jurisdiction shape, name grammar and directory layout? | | 6 |
| Which automation decides by delegation, and for which jurisdictions? | | 6, 7 |

## Roles (chapter 7)

| Question | Answer | Chapter |
| :-------------------------------------------------------- | :-------------------------------- | :---- |
| Which team is accountable for each activity of chapter 7's table? | | 7 |
| Which directory groups hold each role, per jurisdiction? | | 7 |
| Who holds break-glass, and who ratifies? | | 7 |
| Who holds `admin.full_access` and `account_admin`? | | 7 |

## Capacity, availability and recovery (chapter 8)

| Question | Answer | Chapter |
| :-------------------------------------------------------- | :-------------------------------- | :---- |
| How many replicas, on which failure domains? | | 8 |
| PostgreSQL: HA, PITR, keepalives, `max_connections`? | | 8 |
| Vault or OpenBao: HA for Transit and for the stores? | | 8 |
| A second site? Synchronous or asynchronous, and the failover rehearsed? | | 8 |
| How will the load be measured before go-live? | | 8 |
