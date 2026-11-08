# Jurisdictions

## The question

Who decides what? This chapter turns the organisation into a tree of jurisdictions, decides how each workload's jurisdiction follows from its SPIFFE path, which jurisdictions need an approver, which pairs of jurisdictions may bind, and whether tenants are accounts.

A jurisdiction is the area in which some people decide. Within the jurisdiction `cloud/aws`, Alice and Bob approve, while the jurisdiction `dc/traditional` is Carol's. Every source, target and platform belongs to one, and each side of a change is decided within its own.

Jurisdictions live under a charter, as states under a constitution. The **charter** is the set of rules every jurisdiction must comply with: how a workload's jurisdiction follows from its SPIFFE path, each jurisdiction's name prefix, which jurisdictions may bind to which and with whose further consent, and how account jurisdictions are formed. There is one charter per installation, in `server.yaml` under `charter:`. Jurisdictions say who decides; the charter says how jurisdictions are formed and how they may deal with each other. Every change request records the charter in force by its hash, and a change decided under a charter that has since changed is refused. This chapter designs both.

## The jurisdiction tree

A jurisdiction is named by a slash-separated path, and jurisdictions nest like the path's segments. Its shape is yours, but a few rules make it work:

- **One branch per kind of owner.** A data centre is usually flat and short: `dc/corp-prod`, with a team below it, `dc/corp-prod/ledger`. A cloud is deeper: `cloud/<account>/app/<project>` for workloads and `cloud/<account>/data/<tenancy>` for data.
- **Workloads and data on separate branches.** If a project and a tenancy could have the same name and the same jurisdiction, the same people would decide both sides of their binding. With accounts, `ligo` refuses a source jurisdiction that overlaps the target jurisdiction.
- **Parties that only approve get jurisdictions of their own**, such as `sec/infosec` for Information Security.
- **Patterns match whole segments.** `dc/corp-prod/*` covers everything below `dc/corp-prod`, never `dc/corp-production`.

![Example jurisdiction tree: a data centre, a cloud with accounts, and an approving party.](jurisdiction-tree.pdf){width=85%}

## Where a workload's jurisdiction comes from

Nobody chooses a source's jurisdiction: `ligo` derives it from the fixed beginning of the source's SPIFFE ID regex, by one rule per trust domain (`charter.source_jurisdictions`):

| Mode | The jurisdiction is | Fits |
| :---------------- | :---------------------------------------------- | :------------------------------ |
| `static` | One fixed jurisdiction for the whole trust domain | A data centre whose workloads all belong to one owner jurisdiction |
| `path_template` | Taken from the SPIFFE path, such as `/acct/<account>/project/<project>/` to `cloud/<account>/app/<project>` | Tenants, whose SPIFFE paths name them |

A regex whose fixed beginning does not name exactly one jurisdiction is refused. So **the SPIFFE path layout is part of the jurisdiction design**: agree it with the identity team before workloads are registered, and keep the depth fixed across the organisation. The jurisdiction is only as trustworthy as whoever creates the SPIRE entries (chapter 4).

A target's jurisdiction is chosen when it is published, among the patterns its platform allows (`target_jurisdictions`). A platform's own jurisdiction names the team that runs it.

## Who must approve

| Setting | Effect | Use it for |
| :------------------------------------------ | :------------------------------------------ | :------------------------------ |
| `approval.required_jurisdictions` | A side in these jurisdictions needs an approver, a second person | Production, and every account root |
| Not listed | A requester acting for a side approves it automatically | Development, sandboxes |
| `require_distinct_approvers_across_jurisdictions` | A different person on each side | Keep it on |
| Trusted automation | A SPIFFE principal approves sides of its own jurisdictions, by delegation, citing an upstream approval | Pipelines with their own review |
| Break-glass policies | Per jurisdiction: how long an emergency change lasts before it reverts, unless ratified, and how many may be open | Every jurisdiction where people may need to act at night |

Trusted automation is identified by SPIFFE ID, and SPIFFE tells apart where a process runs, not which job it is. Run privileged automation on dedicated nodes, and authorise per job in the automation platform.

## Who may bind to whom

The interconnection policy (`charter.interconnects`) decides which pairs of jurisdictions may bind across jurisdictions:

- **Default deny** for any pair no rule covers. Write the allowed paths, not the forbidden ones.
- **Ordered rules**, the first match wins: put the specific denials (test to production) before broad allows.
- **Additional parties** on an allow rule: a jurisdiction whose approvers must also consent, such as Information Security for a cloud workload reaching a data-centre database.
- **Changing the policy** never removes bindings. Bindings the new policy would deny are logged, audited, announced and counted, for people to decide.

## Accounts

Accounts are for many tenants on shared platforms, run by their own people. Use `charter.accounts` when:

| You have | Without accounts | With accounts |
| :------------------------------------ | :---------------------------------- | :------------------------------------ |
| A few teams | Role grants per jurisdiction in `server.yaml` | Not needed |
| Tens or hundreds of tenants | An edit and a restart per tenant | Registered at run time, through the API or the Accounts page, audited |
| Directory groups per tenant | A rule per group | One rule for every account: `{account}` and `{project}` in the group's DN |
| Shared databases, a schema per tenant | Bounds the same for everyone | `namespace_template` and `grantable_role_templates` keep each tenancy to its own schema |

Plan, once, for every account:

- **The jurisdiction shape**: the account root, the project jurisdiction and the tenancy jurisdiction, as above.
- **The account name grammar**: lowercase letters and digits, starting with a letter. Names that do not fit (`fin-01`) need another layout, or a mapping before registration.
- **The directory layout**: one organisational unit per account, the same depth for all, with operators, approvers and break-glass groups at fixed places.
- **Who registers accounts**: holders of `account_admin`, who see no resources and decide nothing else.
- **The platform approver**: an approver of a shared platform's jurisdiction may decide a binding's target side, for a tenant nobody can reach. The source side still consents, the decision is announced to the target's account, and that account can revoke alone.

## Names

`charter.name_prefixes` gives each jurisdiction its own range of names, such as `ledger-` for `dc/corp-prod/ledger`, so that owners cannot take each other's names. Decide the prefixes with the tree.

## Recommendation

- A data-centre branch with `static` source jurisdictions, a cloud branch with `path_template` and accounts, and a branch for approving parties.
- Every production jurisdiction in `approval.required_jurisdictions`; `ligo` already refuses accounts whose root it does not cover.
- An interconnection policy with default deny, the test-to-production denials first, and Information Security as an additional party on boundary-crossing allows.
- The SPIFFE path layout agreed with the identity team before the first workload is registered.

## When this goes wrong

| Mistake | Consequence |
| :---------------------------------------- | :------------------------------------------------- |
| SPIFFE paths that do not name the owner | Sources are refused (`jurisdiction-unresolvable`), or a whole domain falls into one jurisdiction |
| Projects and tenancies under one branch | The same people decide both sides of a binding |
| `default_cross_jurisdiction: allow` | Every pair may bind unless denied; a forgotten rule opens a path |
| An account name grammar chosen after tenants exist | Names such as `fin-01` cannot be registered; the jurisdiction or SPIFFE layout changes under running workloads |
| Tenants registering their own SPIRE entries | Their workloads can claim another tenant's jurisdiction |
