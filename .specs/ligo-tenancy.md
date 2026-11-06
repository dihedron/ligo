# Accounts and tenancies

This file specifies multitenancy for ligo v0.2.0: hundreds of accounts, each managed by its own people, on shared platforms. It extends ADR-13 (governance scopes), ADR-14 (interconnection) and ADR-15 (first-class resources). Where it differs from `ligo_specification.md`, this file is the proposal and the main specification changes when it is implemented.

Status: draft, 2026-11-06, for review.

## 1. Requirements

1. Operators, approvers and break-glass holders work either across the whole domain or inside one account.
2. An account's SPIFFE IDs contain its account and project in their path, in a configurable structure. A source that does not conform is refused. SPIRE enforces who may hold which ID.
3. On a platform, a tenancy belongs to an account and has a namespace that contains the account and the tenancy's name: on PostgreSQL, the schema `acme_db01`. The platform team creates it outside ligo and registers it. One tenancy is one schema.
4. A binding inside one account is decided by that account's approvers. A binding across accounts needs an approver of each account, except that a platform approver may decide the target's side.
5. Accounts are registered at run time, through the API and a dedicated web page, without editing `server.yaml` or restarting.

v0.1.0 ships without this.

## 2. What does not change

A namespace is a governance scope (§3.9), so the terms Source, Binding, Target, Platform and scope stay, and these rules keep working as they are:

- role grants on scope patterns, so `*` is the whole domain and `cloud/acme/*` one account;
- the `path_template` extractor (requirement 2), which already refuses a regex whose fixed prefix identifies no single scope (`422 scope-unresolvable`);
- two-sided consent, distinct approvers, visibility, break-glass and the interconnection policy;
- targets are register-only: FW-3 stays future work, and no `Tenancy` entity is added, because a tenancy is a target.

## 3. Terms

- **Account**: a registered tenant, with a name and an LDAP organizational unit. New.
- **Project**: the part of an account's workloads below its account, in SPIFFE paths and source scopes. A source scope, not an entity.
- **Tenancy**: a target on a namespaced platform. A target scope, not an entity.
- **Namespace**: the name of a tenancy's resource on the platform, computed from its scope (§5).

## 4. The structure of scopes

`governance.accounts` in `server.yaml` declares the structure once:

```yaml
governance:
  accounts:
    scope: "cloud/{account}"                  # the account's root
    source_scope: "cloud/{account}/app/{project}"
    target_scope: "cloud/{account}/data/{tenancy}"
    ldap_groups:                              # §8
      search_base: "ou=accounts,dc=corp,dc=internal"
      roles:
        - { group_dn: "cn=operators,ou={account},ou=accounts,dc=corp,dc=internal",  role: operator,    scope: "cloud/{account}/*" }
        - { group_dn: "cn=approvers,ou={account},ou=accounts,dc=corp,dc=internal",  role: approver,    scope: "cloud/{account}/*" }
        - { group_dn: "cn=breakglass,ou={account},ou=accounts,dc=corp,dc=internal", role: break_glass, scope: "cloud/{account}/*" }
        - { group_dn: "cn=operators,ou={project},ou={account},ou=accounts,dc=corp,dc=internal", role: operator, scope: "cloud/{account}/app/{project}" }
        - { group_dn: "cn=approvers,ou={project},ou={account},ou=accounts,dc=corp,dc=internal", role: approver, scope: "cloud/{account}/app/{project}" }
  source_scopes:
    - trust_domain: cloud.internal
      mode: path_template
      path_regex: '^/acct/([a-z][a-z0-9]*)/project/([a-z][a-z0-9]*)/'
      scope_template: 'cloud/${1}/app/${2}'
```

Sources and targets sit on separate branches, `app` and `data`, because a project and a tenancy with the same name would otherwise be one scope, with the same people deciding for both sides of their binding.

Rules, checked at startup (§8.2):

1. `{account}`, `{project}` and `{tenancy}` each match one whole segment, and each value MUST match `^[a-z][a-z0-9]*$`. This is narrower than a scope segment on purpose: see §5.
2. A scope is **account-managed** when it matches the form of `scope` or lies below it. All others, such as `dc/corp-prod`, need no account and behave as in v0.1.0. `source_scope` and `target_scope` MUST lie below `scope`. They MUST NOT overlap, so that a project and a tenancy of one name can never be one scope.
3. `ldap_groups` patterns may use `{account}` and `{project}`, and every placeholder of a rule's `scope` MUST appear in its `group_dn`. A rule's role is `viewer`, `operator`, `approver` or `break_glass`: never `trusted_automation`, which is for machines, or a global role. Tenancies have no groups of their own: the account's approvers and the platform's decide for them.
4. The whole section is optional. Without it, ligo behaves as v0.1.0.

Static role bindings keep working and add to these grants. People with `*` or `cloud/*` are the domain-wide operators and approvers of requirement 1.

## 5. Namespaces (gap 1)

**Problem.** A target's scope and its definition are unrelated today: `ValidateTargetRequest` carries no scope, so an operator of `cloud/acme/data/db01` can publish `{"schema": "globex_db02"}`, and only the platform owner's approval stops it.

**Decision.** A platform declares its namespace in `server.yaml`:

```yaml
platforms:
  - name: pg-shared
    target_scopes: ["cloud/*"]
    namespace_template: "{account}_{tenancy}"
```

A platform provider declares which field of its definition holds the namespace, in a new capability:

```proto
message PlatformProviderCapabilities {
  repeated IdentityMode accepted_identity_modes = 1;
  string client_output_schema_json = 2;
  string namespace_field = 3;   // a top-level field of the definition; empty: no namespaces
}
```

`ligo-plugin-postgres` declares `schema`. A platform with a `namespace_template` whose plugin declares none is refused at startup.

**Check.** On publishing a target or changing its definition, and again when a change request is re-validated at approval, the engine:

1. matches the target's scope against `target_scope`; no match: `422 namespace-scope-mismatch`;
2. expands the template with the values matched;
3. compares the result, exactly, with `namespace_field` of the **normalized** definition the plugin returned; a difference: `422 namespace-mismatch`, naming the expected value.

The engine does the comparison, not each plugin, so a plugin cannot get it wrong or forget it, and a plugin needs no knowledge of scopes. At startup, every existing target of a namespaced platform is checked; a mismatch is a fatal error naming it.

**No character mapping.** Values are never transformed. Mapping `-` to `_` would make two tenants collide: account `a-b` with tenancy `c`, and account `a` with tenancy `b-c`, would both give `a_b_c`. Because values cannot contain `_`, and a template's literal separators are checked at startup to contain a character the values cannot hold, the expansion is injective: two tenancies never share a namespace.

**Case.** Scopes are lower case, so schemas and SPIFFE paths are too. SPIFFE IDs are case-sensitive, so `/acct/ACME/` is refused. LDAP names are not, so `ou=ACME` in a DN reads as `acme` (§8).

## 6. Tenant roles (gap 2)

**Problem.** `grantable_roles` is one flat list per platform, unrelated to the schema, so ACME's target can offer a role meant for Globex's schema. Gap 1 alone would leave this open, because the grant is what gives access.

**Decision.** `ligo-plugin-postgres` gains `grantable_role_templates`, with `{namespace}` standing for the target's schema:

```yaml
config:
  grantable_role_templates: ["{namespace}_read", "{namespace}_write"]
  grantable_roles: []        # deliberately shared roles only
```

The bound of a level is the union of `grantable_roles` and the templates expanded with the definition's schema. The plugin already receives the definition in `ValidateTarget` and `ValidateBinding`, so **no proto change** is needed. It is checked in those two calls and again in `EnsureTarget`.

- The platform team creates the roles with the schema, and gives the admin role `ADMIN OPTION` on them. That is part of the external tenancy procedure.
- `GetUISchemas` cannot list per-namespace options before the schema is known: `roles` takes the template's expansions once the schema is entered.
- With `namespace_template` set and a non-empty `grantable_roles`, startup logs a warning: those roles are shared across tenants.
- Other plugins with roles on shared systems follow the same rule when they gain namespaces.

## 7. Accounts

### 7.1 Registry

```sql
CREATE TABLE accounts (
    name          VARCHAR(30) PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9]*$'),
    display_name  VARCHAR(255),
    status        account_status NOT NULL DEFAULT 'ACTIVE',   -- ACTIVE | RETIRED
    registered_by VARCHAR(255) NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_by    VARCHAR(255),
    retired_at    TIMESTAMPTZ
);
```

`sources` and `targets` gain `account VARCHAR(30) REFERENCES accounts ON DELETE RESTRICT`, computed from the scope, and NULL outside account-managed scopes. A trigger refuses a new source or target on a `RETIRED` account, and refuses retiring an account while it has one that is not `RETIRED`. This goes into `001`, edited in place: no deployment of v0.1.0 exists, so there is no migration or backfill.

The 30-character limit keeps `{account}_{tenancy}` within PostgreSQL's 63 characters together with a tenancy of up to 32; a longer result fails the plugin's identifier grammar and is refused.

### 7.2 Lifecycle

- **Registering applies at once**, with no change request, and is audited (`ACCOUNT_REGISTERED`). It grants nothing by itself: no source or target exists yet, and those still need consent.
- **Retiring** needs no active resources (`409 account-in-use`) and is audited (`ACCOUNT_RETIRED`). A retired account's name is never reused, because audit entries and SPIFFE paths refer to it.
- **An unregistered or retired account is refused** on an account-managed scope: `422 account-not-registered`, when a source is registered and a target published, and again when a change request is re-validated at approval.
- Replicas learn of changes through `LISTEN`/`NOTIFY`, as the resolution cache does (§4.5), with its periodic full reload.

### 7.3 Who may do it

A new role, `account_admin`, bound in `server.yaml`, global, with no scope. It may register, retire and list accounts, and nothing else: it decides no change request and does not see resources. `admin.full_access` includes it.

### 7.4 API, CLI and UI

| Route | Role | Result |
|---|---|---|
| `POST /v1/admin/accounts` | `account_admin` | `201`; `409 account-exists` |
| `GET /v1/admin/accounts` | `account_admin`, or a role on the account (only those accounts) | A paged list |
| `GET /v1/admin/accounts/{name}` | as above | The account and its counts of sources, targets and bindings |
| `POST /v1/admin/accounts/{name}/retire` | `account_admin` | `200`; `409 account-in-use` |

CLI: `ligo account list|get|register|retire`. UI: an **Accounts** page, shown to those roles, with register and retire forms, following the same templates, CSRF and `samples()` conventions as the other pages (TestTemplates, TestINV11Routes, TestINV12).

### 7.5 What stays in `server.yaml`

Platforms (plugin wiring, bootstrap credentials, privilege bounds), the interconnection policy, approval requirements, extractors, and `governance.accounts` itself. ADR-14 rule 8 and T-22 keep guardrails out of the API so that ligo's administrators cannot weaken rules they are subject to. Only data about tenants moves to the database.

## 8. Roles from LDAP

**Problem.** Every group is listed in `server.yaml`, and a login checks each listed group with one search (`adminauth.member`). With hundreds of accounts, that means a config change and a restart per tenant, and over a thousand searches per login.

**Decision.** One rule for all accounts, from §4 `ldap_groups`:

1. At login and at each session recheck (`Lookup`), one subtree search under `search_base` finds the user's groups, with the existing `group_membership_filter`.
2. Each DN is parsed with `ldap.ParseDN`, never matched as text, and compared with each `group_dn`, RDN by RDN, ignoring case. It MUST have the same number of RDNs as the rule. A placeholder must be one whole attribute value and, lower-cased, match `^[a-z][a-z0-9]*$`. A DN that does not fit is ignored.
3. A match gives the rule's role on the rule's scope, **only if the account is registered and `ACTIVE`**. Projects are not registered: the group's existence under the account's OU is enough.

**Depth.** The positions of the account and the project are configuration, fixed by the rules' `group_dn`, and hold for the whole organisation. A directory with the account at depth 5 and the project at depth 7 writes its rules that way, and no code changes. Every RDN of a rule that is not a placeholder is a literal, so OUs between them must have the same name everywhere. Startup checks that `{account}` is at the same depth in every rule and `{project}` at the same depth in every rule that has one.

`Authorizer.For` returns the union of these and the static bindings. `nested_groups` does not apply to the derived rule: only direct membership counts.

**Trust boundary.** Whoever can create groups or add members under an account's OU can grant ligo roles in that account. The directory's access rules become part of ligo's security model (T-37), and the registry only limits this to registered accounts.

## 9. Approvals

### 9.1 Configuration

```yaml
governance:
  interconnects:
    default_cross_scope: deny
    rules:
      - { name: accounts, from: ["cloud/*"], to: ["cloud/*"], action: allow }
authorization:
  approval:
    required_scopes: ["cloud/*"]
```

Without `required_scopes`, an account operator's own sides would be approved automatically (`AUTO`), and nobody would approve a binding inside the account. Startup refuses `governance.accounts` when `required_scopes` does not cover `scope`.

### 9.2 Who decides a binding

| Binding | `SOURCE` side | `TARGET` side |
|---|---|---|
| Same account | An approver of the account | An approver of the account, or of the platform |
| Across accounts | An approver of the source's account | An approver of the target's account, or of the platform |

Both of the existing rules apply: the requester never decides, and `require_distinct_approvers_across_scopes` still asks for two different people. `app` and `data` are separate branches, so a binding inside an account always has two sides and needs two people: a project's approver can decide `SOURCE`, and an account's approver either side. An account with one approver cannot approve its own bindings; a waiver will be added only if that proves necessary, and it needs a new "same account" form of rule, as patterns cannot express it.

### 9.3 The platform approver (new)

An approver of a binding's **platform scope** also qualifies for its `TARGET` side, for create, raising a level and changing parameters, and for ratifying a `BREAK_GLASS` `TARGET` side.

- The check moves from `CanApprove(side.Scope)` to one function taking the request and the side, called from all four sites: `changerequests.go:294` and `:358`, `ui/decisions.go:79`, and `ui/bindings.go:120`, and from the `--awaiting-me` query (`service.go:680`). The `TARGET` side's `scope` stays the target's, and no new side or basis is added, so the database triggers of ADR-13 rule 9 hold as they are.
- The audit entry and the side show who decided, and the entry adds `decidedAs: PLATFORM`.
- It never applies to `SOURCE`, `OWNER`, `PARTY:` or any other side.
- `AUTO` is not extended: a platform operator filing a binding gets no automatic `TARGET` side.

**Why not let a platform approver decide alone.** That would remove the source account's consent: they could send another account's workloads connection details, and possibly credentials, for a target they control. This is the credential injection of ADR-13, and it is refused.

**What this does give up.** The target's account no longer has to consent. An ACME approver and a platform approver together can bind an ACME workload to a Globex schema without Globex taking part. This is decided, for the case of a tenant nobody can reach. Three things bound it: the platform team already runs that database; the decision is audited and raises the `BINDING_TARGET_DECIDED_BY_PLATFORM` webhook event to the target's account; and that account can revoke alone (consent `ANY`). See R-12.

### 9.4 Trust domains and the secret store (constraint)

A binding using a secret store works only if the store accepts the JWT-SVIDs of the source's trust domain, or the workload cannot read its credential. So an account's SPIFFE IDs MUST be in the trust domain of the store's zone, or a trust relationship MUST be established, by configuring the store's JWT auth for that trust domain. On the lab, `bao-prod` and `vault-prod` refuse `test.lab` JWT-SVIDs, for this reason.

ligo does not check this: the binding reaches `ACTIVE`, and the failure appears when the workload reads. The Setup Guide and Operator's Guide state the constraint.

## 10. Security

New entries for the threat and risk tables of the main specification:

| ID | Threat | Mitigation |
|---|---|---|
| T-37 | Someone who can write under an account's OU grants themselves roles in it | Only registered accounts; exact DN parsing; the directory's access rules, documented as part of the deployment |
| T-38 | A target claims another tenant's schema or roles | §5 and §6, checked by the engine and the plugin, at filing and at approval |
| T-39 | A DN crafted to read as another account (escaped commas, extra attributes) | `ldap.ParseDN`, attribute comparison, the account grammar |

| ID | Residual risk |
|---|---|
| R-12 | A platform approver can decide a target's side without its account (§9.3) |
| R-13 | A tenant's isolation on a shared PostgreSQL rests on the schema and role privileges the platform team sets up outside ligo; ligo checks names, not what the roles actually grant |

T-29 and R-08 (SPIRE registration) are unchanged, and matter more here: account isolation rests on who can register under `/acct/<account>/`.

## 11. Tests and chunks

**Acceptance scenarios** (U unit, I integration, L lab):

| ID | Given | When | Then | Level |
|---|---|---|---|---|
| TN-1 | Template `{account}_{tenancy}` | Scope `cloud/acme/data/db01`, schema `globex_db02` | `422 namespace-mismatch`, also at approval | I |
| TN-2 | A role of another namespace | A level grants `globex_db02_read` on `acme_db01` | Refused by `ValidateTarget` | U, L |
| TN-3 | Values `a-b`, `c` and `a`, `b-c` | Registering; expanding | Refused by the grammar | U |
| TN-4 | No such account | Register a source or publish a target | `422 account-not-registered` | I |
| TN-5 | A retired account | A pending request is approved | Refused at re-validation | I |
| TN-6 | An account with a source | Retire | `409 account-in-use` | I |
| TN-7 | A user in `cn=approvers,ou=acme,…` | Login | `approver` on `cloud/acme/*`, not on `cloud/globex/*` | L |
| TN-8 | The account retired; group unchanged | Session recheck | The grant is gone | I |
| TN-9 | Hostile DNs: `ou=acme\,ou=globex`, an extra RDN, a missing RDN | Parsing | No grant; `ou=ACME` reads as `acme` | U |
| TN-10 | Same account | Operator files; two approvers of it decide | `APPLIED` | L |
| TN-11 | Across accounts | An ACME approver decides `TARGET` of a Globex binding | `403` | I |
| TN-12 | Across accounts | ACME approver and platform approver | `APPLIED`, `decidedAs: PLATFORM`, webhook to Globex | L |
| TN-13 | A platform approver | Decides `SOURCE`; decides alone | `403`; stays `PENDING` | I |
| TN-14 | The platform approver filed it | Decides `TARGET` | Refused: the requester never decides | I |
| TN-15 | Register on one replica | Login on the other at once | Effective within the notify delay | L |
| TN-16 | An existing target that does not match | Startup | Fatal, naming it | I |
| TN-17 | Every account route, each role | Mutating without `account_admin` | `403`, audited | I |
| TN-18 | A user in `cn=approvers,ou=app01,ou=acme,…` | Login | `approver` on `cloud/acme/app/app01`, not on `cloud/acme/app/app02` or `cloud/acme/data/*` | L |
| TN-19 | Rules with the account at depth 5 and the project at depth 7; a rule with the account elsewhere | Startup | Accepted; refused | U |

**Chunks**, each its own commit, on one branch per PR:

1. `governance.accounts`, its startup rules, template expansion (U).
2. The registry in `001`, its API, CLI and triggers.
3. Namespaces: capability, engine check, startup check, `ligo-plugin-postgres` `namespace_field`.
4. `grantable_role_templates`.
5. Roles from LDAP: subtree search, DN parsing, the union in `Authorizer`, cache and recheck.
6. The platform approver on `TARGET`, with the audit field and webhook event.
7. The **Accounts** web page.
8. Lab: scenario with two accounts (`acme`, `globex`), OUs in `ldap/seed.ldif`, a shared PostgreSQL with both tenancies, and TN-7, 10, 12, 15, 18; on OpenBao then Vault. Operator's Guide and Setup Guide, with the constraint of §9.4.
