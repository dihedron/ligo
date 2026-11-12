# One `ligo` or several

## The question

Should one installation serve the whole organisation, or should there be several, for example one per environment, per network zone or per regulator? And if several, what may they share?

## What one installation already separates

Much separation needs no second installation. Inside one, `ligo` keeps apart:

| Separation | By |
| :---------------------------------- | :------------------------------------------------------------ |
| Who decides | Jurisdictions: every resource has an owner jurisdiction, and each side of a change is decided by its own jurisdiction's people |
| Who may bind to whom | The interconnection policy: ordered allow and deny rules on pairs of jurisdictions, deny by default; test can be kept from production whoever agrees |
| Who sees what | Visibility: a binding exists only for those holding a role on its jurisdictions; everyone else gets `404` |
| Whose names are whose | Name prefixes per jurisdiction |
| Which identities plugins hold | Realms: one plugin process per type and realm, each with its own SVIDs |
| Four eyes | Distinct approvers per side, enforced by the database |

So "production and test must not be bound to each other" is a rule of the interconnection policy, not a reason for two installations.

## What only separate installations separate

Some things are one per installation, and only a second installation divides them:

| Shared inside one installation | Why it may matter |
| :---------------------------------------------- | :------------------------------------------------- |
| The database | Its administrators can read every resource and the whole audit; one restore restores everything; one outage stops every change |
| `server.yaml` and its owners | One platform team owns the plugin types, their bounds and the policy; platforms are owned by the jurisdictions that run them |
| The `ligo` hosts | Their plugins hold, or obtain with their SVIDs, the administrative access to every platform, and must reach every one of them |
| `ligo`'s core identity and Transit key | One sealing key for all inter-stage secrets |
| Upgrades and maintenance mode | One version, one maintenance window, for everyone |
| The admin listener | One place where every administrator signs in |
| Failure domain | A fault of `ligo` or its database affects every binding at once |

## The criteria

| Criterion | Points to one installation | Points to several |
| :------------------------------ | :---------------------------------- | :-------------------------------------- |
| Regulation, data residency | One regime | Regimes that forbid shared administration or shared data |
| Administration | One platform team | Teams that must not hold each other's platform credentials |
| Network | `ligo` hosts may reach every platform | Network zones that a central host must not reach |
| Blast radius | Acceptable for the whole | A compromise of one must not reach the other |
| Availability | One failure domain is acceptable | Independent failure, for example per site |
| Change cadence | One upgrade window suits all | Different windows, for example a stricter one for production |
| Cross-boundary bindings | Frequent | Rare, or forbidden |
| Cost | Fewer people and services | Each installation costs its own replicas, database, agents, Transit key and operations |

## Across installations

A binding links a source and a target of the same installation. A workload can still use targets of several installations: each installation that accepts its trust domain can register it as a source, and the workload asks each one for its bindings. What does not cross is consent: each installation has its own charter, approvers and audit, and a binding that spans two installations does not exist.

Separate installations can share infrastructure without sharing what matters:

| Shared | How | What stays shared |
| :---------------------- | :------------------------------------------------------------ | :------------------------------ |
| A PostgreSQL cluster | A database and four roles per installation | The cluster's administrators and its failure domain |
| A Vault or OpenBao cluster | A Transit key per installation (`secret_sealing.vault_transit.key_name`, or a mount) | The cluster's administrators and its availability |
| SPIRE | Each installation's hosts run their own agents | The trust domain and its administrators |
| The directory | Groups per installation | The directory's administrators |

## Recommendation

- **Start with one installation**, and separate with jurisdictions, the interconnection policy and realms.
- **Add an installation for a boundary the table of what only installations separate cannot cross**: a regulator, a network zone central hosts must not reach, a team that must not hold another's platform credentials, or an independent failure domain.
- **Between installations, share clusters only where their administrators are trusted by both**, and never the Transit key.
- **Write down, for each installation, which jurisdictions and trust domains it serves**, so that every target has exactly one home.

## When this goes wrong

| Mistake | Consequence |
| :---------------------------------------- | :------------------------------------------------- |
| One installation per environment, only to keep test from production | Twice the operations; the interconnection policy would have done it |
| One installation across a regulatory boundary | One database and one platform team hold both sides |
| Central `ligo` hosts reaching into a protected network zone | Firewall exceptions from a host that holds every platform's credentials |
| Several installations sharing one Transit key | A compromise of one unseals the other's inter-stage secrets |
| No record of which installation owns which jurisdictions | Two installations accept the same target, and decisions about it split |
