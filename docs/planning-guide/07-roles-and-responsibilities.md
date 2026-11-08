# Roles and responsibilities

## The question

Who holds which role in `ligo`, which team is responsible for each part around it, and which separations of duty does `ligo` enforce, and which must the organisation enforce itself?

## The roles `ligo` knows

Roles are granted on jurisdiction patterns, to a directory group or to a SPIFFE ID.

| Role | May | Held by |
| :------------------ | :---------------------------------------------- | :------------------------------ |
| `viewer` | Read what its jurisdictions can see | Anyone who needs to look: auditors, support |
| `operator` | File changes for its jurisdictions | Source and target owners; the platform team for its platforms |
| `approver` | Decide its jurisdictions' sides of a change | Leads of each team, a different person from the operator |
| `break_glass` | Apply an emergency change at once; a create or update is reverted unless ratified | A few people per jurisdiction, on call; people only |
| `trusted_automation` | File changes whose sides in its jurisdictions are approved by delegation | A pipeline's SPIFFE ID; never a person |
| `account_admin` | Register, retire and list accounts; nothing else | Whoever onboards tenants |
| `admin.full_access` | Everything, maintenance and recovery included, except deciding its own requests | Very few; the platform team's leads |

With accounts, every account's operators, approvers and break-glass holders come from its own directory groups, through one rule for all accounts.

## The people around `ligo`

| Team | Responsible for |
| :--------------------- | :------------------------------------------------------------ |
| Platform team | `server.yaml`: realms, platforms, privilege bounds, the interconnection policy, accounts' structure; the `ligo` hosts, upgrades, plugins |
| Identity team | SPIRE servers and agents; registration entries for `ligo`, its plugins and every workload |
| Database team | PostgreSQL: availability, backups, restores, roles |
| Secrets team | Vault or OpenBao: the Transit key, the stores, their authentication |
| Directory team | LDAP: people, groups, the lockout policy |
| Network team | The load balancer, firewalls, the flows each network zone needs |
| Source and target owners | Their sources, targets and bindings; approving their sides |
| Security (InfoSec) | The interconnection policy's content; approving as an additional party; the audit in the SIEM |
| On call | Monitoring, incidents, break-glass |

## Who does what

R: does it. A: answers for it (one per row). C: consulted. I: informed.

::: landscape

| Activity | Platform | Identity | Database | Secrets | Owners | Security | On call |
| :------------------------------------------ | :------ | :------ | :------ | :------ | :------ | :------ | :------ |
| Change `server.yaml` (platforms, bounds, policy) | A, R | C | | C | I | C | I |
| Register or retire an account | A, R (`account_admin`) | C | | | I | I | |
| Register workloads in SPIRE (and tenants' paths) | C | A, R | | | C | I | |
| Register a source | | | | | A, R | | |
| Publish a target on a platform | C (platform side) | | | | A, R | | |
| Create a binding | | | | | A, R (both sides) | C (as a party) | |
| Revoke a binding | C | | | | A, R (either side) | I | R |
| Emergency change (break-glass) | I | | | | A (ratify) | I | R |
| Upgrade `ligo` or a plugin | A, R | R (entries) | C | | I | I | I |
| Back up and restore the database | C | | A, R | | | | I |
| Rotate the Transit key | C | | | A, R | | | |
| Review the audit | | | | | | A, R | |
| Respond to an alert | C | C | C | C | | | A, R |

:::

## Separation of duties

`ligo` enforces some separations itself, many of them in the database, so that a bug or the application's own database role cannot get around them:

- **Maker and checker.** Where approval is required, a second person decides each side; nobody decides their own request, `admin.full_access` included.
- **Distinct approvers across sides** (`require_distinct_approvers_across_jurisdictions`, on by default).
- **People only** for break-glass and for ratifying it; **SPIFFE IDs only** for trusted automation.
- **Account administrators see nothing**: they register accounts and decide no changes.

The organisation must enforce the rest, because `ligo` cannot see it:

| Separation | Why `ligo` cannot enforce it |
| :---------------------------------------------- | :------------------------------------------------- |
| Who is in which directory group | `ligo` trusts the directory's answer |
| Who creates SPIRE entries, especially tenants' paths | A jurisdiction derived from a path is only as good as who assigns the path |
| Who changes `server.yaml` | It is root-owned on the hosts; its change control is the platform team's |
| Who has root on `ligo` hosts and automation nodes | Root obtains the host's identities |
| Who administers the database | Its administrators can bypass the application and its triggers |
| Which job runs under an automation's identity | SPIFFE tells apart where a process runs, not which job it is |

## Directory groups

Plan the groups with the jurisdiction tree (chapter 6): per jurisdiction, one group each of operators, approvers and break-glass holders; one group of viewers; one of account administrators; one of full administrators. With accounts, the same three groups sit at the same place in every account's organisational unit. Keep the operator and approver groups of one jurisdiction disjoint, so that maker and checker are always two people.

## Automation

Give each automation its own SPIFFE ID per set of jurisdictions, issued only on nodes dedicated to the automation platform, in a context people cannot enter: a container selected by namespace, service account and image digest, or a dedicated uid with no login. A person running the same tool from their own machine must not get that identity. The *Setup Guide* lists the requirements; plan the nodes and their owners here.

## Recommendation

- One accountable team per row of the activity table, written down before go-live.
- Operator and approver groups disjoint, per jurisdiction.
- Break-glass holders few, named, and on call; every ratification by someone else.
- `admin.full_access` for very few people, and never for automation.
- The identity team, not tenants, creates tenants' SPIRE entries.

## When this goes wrong

| Mistake | Consequence |
| :---------------------------------------- | :------------------------------------------------- |
| One group both operates and approves | Two people are still needed, but any two of the same team will do |
| Tenants create their own SPIRE entries | A tenant can take another's bindings |
| `admin.full_access` widely held | Many people can change maintenance and recovery, and act in every jurisdiction |
| Automation on shared hosts | A person on that host acts with the automation's approval power |
| No owner for upgrades' SPIRE entries | An upgrade leaves `ligo` or a plugin without an SVID |
