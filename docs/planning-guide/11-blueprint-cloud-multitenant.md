# Blueprint: a multitenant cloud

## Context and assumptions

A private cloud in one network zone, hosting hundreds of accounts. Each account belongs to a customer team that runs its own projects and wants its own databases, without filing tickets with the platform team for every binding. The platform team runs shared PostgreSQL servers, with one schema per tenancy, and must not become the bottleneck. Accounts come and go every week.

## Layout

![A multitenant cloud: one trust domain, accounts as jurisdictions, one shared database platform.](bp-cloud-multitenant.pdf){width=90%}

| Element | Choice | Chapter |
| :------------------------ | :---------------------------------------------- | :---- |
| Trust domains | One, `cloud.internal`, for every account | 3 |
| Realms | One, `cloud` | 3 |
| SPIRE | One HA server cluster; a registrar under the identity team's control creates every account's entries | 4 |
| Installations | One | 5 |
| Accounts | `charter.accounts`; registered at run time by `account_admin` | 6 |
| Shared database | `pg-shared`, one schema `<account>_<tenancy>` per tenancy | 6 |
| Store | One Vault or OpenBao in the cloud domain, so it trusts every account's JWT-SVIDs | 3 |

## Jurisdictions

Every account has the same shape, declared once:

| Jurisdiction | Owns | Decided by |
| :---------------------------------- | :---------------------------- | :------------------------------------ |
| `cloud/<account>` | The account's root | The account's approvers |
| `cloud/<account>/app/<project>` | A project's sources | The account's approvers |
| `cloud/<account>/data/<tenancy>` | A tenancy, one schema on `pg-shared` | The account's approvers, or the platform approver |
| `ops/platform` | The shared platforms | The platform team's leads |

A workload's SPIFFE path names its account and project, `spiffe://cloud.internal/acct/<account>/project/<project>/…`, so its jurisdiction follows. The shared platform's `namespace_template` ties each tenancy to its schema, and `grantable_role_templates` to that schema's roles, so that no tenant can offer another's:

```{.yaml include="docs/planning-guide/examples/cloud-multitenant.yaml" keys="charter"}
```

Inside one account, two of its approvers decide a binding. Across accounts, an approver of each account consents. When a tenant cannot be reached, an approver of `ops/platform` may decide the target side; the source account still consents, the target account is told, and it can revoke alone.

## Roles

```{.yaml include="docs/planning-guide/examples/cloud-multitenant.yaml" keys="authorization"}
```

| Activity | Who |
| :---------------------------------------- | :------------------------------------------ |
| Register an account | `account_admin`, after the directory unit and the SPIRE registrar are ready for it |
| Create a tenancy's schema and roles | Platform team, outside `ligo`; then the account publishes the target |
| The account's groups (`operators`, `approvers`, `breakglass`) | The directory team, at the account's request; never the account itself |
| SPIRE entries under `/acct/<account>/` | The registrar; never the account |
| Bindings inside the account | The account's operators file; two of its approvers decide |
| Bindings across accounts | Both accounts' approvers |
| Emergency changes in an account | The account's break-glass group, ratified by its approvers |

Onboarding an account is therefore four steps by three teams: a directory unit with its groups, the registrar's permission for `/acct/<account>/`, the registration in `ligo`, and the first schema. Write it down as one procedure.

## Capacity and availability

Hundreds of accounts change nothing in `ligo`'s shape: accounts are rows, roles are one rule, and jurisdictions are paths. The registry is reloaded on change, without restarts. What grows is the number of bindings, and that is chapter 8's sizing method. On the lab, a test with 300 accounts, changes racing the retirement of accounts, replicas killed and PostgreSQL restarted passed once; longer runs are planned in the soak.

The shared database is the tenants' common failure domain: plan its capacity and availability for all of them.

## Failure analysis

| Failure | Effect | Mitigation |
| :---------------------------- | :------------------------------------------------ | :---------------------------------- |
| A tenant's SPIRE registrar is compromised | It can register workloads into other accounts' paths | The registrar is the identity team's; tenants never hold it |
| A directory administrator adds a member to an account's group | That person gets the account's roles | Restrict writes under `ou=accounts` like `server.yaml` |
| An account must leave | `ligo` refuses to retire it while it has active resources (`account-in-use`); its name is never reused | Offboarding retires its sources and targets first, as the mirror of onboarding |
| The shared database | Every tenancy on it | Database HA; several shared databases for large populations |

## Variations

- **Several shared databases**, by size or by tenant class: one platform each, all with the same `namespace_template`.
- **Dedicated databases** for some accounts: a platform per account, with `target_jurisdictions: ["cloud/<account>/*"]`.
- **Automation per account**, with `trusted_automation` on the account's jurisdictions, on the account's dedicated runners.

## Checklist

- [ ] Account name grammar: lower-case letters and digits, starting with a letter
- [ ] SPIFFE path layout: `/acct/<account>/project/<project>/…`, registered only by the registrar
- [ ] Directory: one unit per account under `ou=accounts`, three groups each, writes restricted
- [ ] `required_jurisdictions` covering `cloud/*`
- [ ] Shared databases with `namespace_template` and `grantable_role_templates`
- [ ] The store in the cloud trust domain
- [ ] An onboarding and an offboarding procedure, across the directory, SPIRE, `ligo` and the database
