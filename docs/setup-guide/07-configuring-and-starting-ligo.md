# Configuring and starting ligo

## The files

| File | Owner, mode | Holds |
| :------------------- | :-------- | :-------------------------- |
| `/etc/ligo/server.yaml` | `root:ligo`, `0640` | The configuration: no secrets, only the names of environment variables |
| `/etc/ligo/ligo.env` | `root:ligo`, `0640` | The DSNs, the bind password, webhook secrets, the replica's ID |

Start `server.yaml` from `/usr/share/ligo/examples/server.yaml`, which shows every key. The chapter *Configuration reference* explains them. The smallest useful parts are below.

## `ligo.env`

```bash
LIGO_INSTANCE_ID=ligo1
LIGO_PG_APP_DSN='host=db.internal dbname=ligo sslmode=verify-full user=ligo_app password=<password>'
LIGO_PG_READER_DSN='host=db.internal dbname=ligo sslmode=verify-full user=ligo_reader password=<password>'
```

Add `LIGO_PG_DBOS_DSN` in the same form, with `user=ligo_dbos`; the variable that `admin_auth.ldap.service_bind_password_env` names, with the directory's bind password, and each webhook's `hmac_secret_env`.

**`LIGO_INSTANCE_ID` must be unique and stable.** A replica that dies must come back under the same ID: only then do its workflows resume.

## Identity and listeners

```yaml
service:
  instance_id_env: "LIGO_INSTANCE_ID"
  workload_advertise: { destination: "ligo.prod.internal", port: 8443, server_name: "ligo.prod.internal" }
realms:
  - { name: prod, trust_domain: prod.internal, spiffe_workload_socket: "unix:///run/spire/prod/agent.sock" }
core_identity:
  realm: prod
  svid_selector:
    match_expr: 'path == "/ns/sys/sa/ligo"'
    jwt_audience: ["https://vault.prod.internal"]
server:
  workload_listener:
    listen_address: "0.0.0.0:8443"
    tls_source: spiffe
    auth_modes: [x509_svid, jwt_svid]
    accepted_trust_domains: [prod.internal]
    expected_jwt_audience: "spiffe://prod.internal/ns/sys/sa/ligo"
  admin_listener:
    listen_address: "0.0.0.0:9443"
    external_origin: "https://ligo-admin.corp.internal:9443"
    tls_source: spiffe
    client_svid_auth: { enabled: true, accepted_trust_domains: [prod.internal] }
```

`external_origin` must be exactly the address browsers use: the web UI checks it against each request's origin.

## Who may do what

Roles are granted on jurisdiction patterns. A pattern matches whole segments only, and `*` matches the jurisdiction and everything below it.

| Role | May |
| :---------- | :-------------------------------- |
| `viewer` | Read |
| `operator` | File changes for the jurisdiction |
| `approver` | Decide the jurisdiction's sides |
| `break_glass` | Apply emergency changes. People only, by `ldap_group_dn` |
| `trusted_automation` | File changes approved by delegation. SPIFFE principals only, with a reference to an upstream approval |
| `admin.full_access` | All of the above except deciding one's own requests, and maintenance and recovery |
| `account_admin` | Register, retire and list accounts, and nothing else. Global: it takes no `jurisdictions`. `admin.full_access` includes it |

```yaml
authorization:
  bindings:
    - { ldap_group_dn: "cn=ligo-viewers,ou=groups,dc=corp,dc=internal", role: viewer, jurisdictions: ["*"] }
    - { ldap_group_dn: "cn=ledger-dbas,ou=groups,dc=corp,dc=internal", role: operator, jurisdictions: ["dc/corp-prod/*"] }
    - { ldap_group_dn: "cn=ledger-leads,ou=groups,dc=corp,dc=internal", role: approver, jurisdictions: ["dc/corp-prod/*"] }
  approval:
    required_jurisdictions: ["dc/corp-prod/*"]
charter:
  source_jurisdictions:
    - { trust_domain: prod.internal, mode: static, jurisdiction: "dc/corp-prod" }
  interconnects:
    default_cross_jurisdiction: deny
    rules:
      - { name: dc-to-apps, from: ["dc/corp-prod"], to: ["dc/corp-prod/*"], action: allow }
```

The **charter** is the set of rules every jurisdiction must comply with: how a workload's jurisdiction follows from its SPIFFE path, each jurisdiction's name prefix, which jurisdictions may bind to which and with whose further consent, and how account jurisdictions are formed. There is one charter per installation, in `server.yaml` under `charter:`. Jurisdictions say who decides; the charter says how jurisdictions are formed and how they may deal with each other. Every change request records the charter in force by its hash, and a change decided under a charter that has since changed is refused.

Each trust domain a platform accepts needs one `source_jurisdictions` entry. Across jurisdictions, `ligo` denies by default: add a rule for each flow you intend.

## Accounts

Accounts let many tenants share platforms, each managed by its own people. They are optional. Tenants are registered at run time; only their common structure goes in `server.yaml`:

```yaml
authorization:
  bindings:
    - { ldap_group_dn: "cn=ligo-account-admins,ou=groups,dc=corp,dc=internal", role: account_admin }
  approval:
    required_jurisdictions: ["cloud/*"]    # startup refuses accounts this does not cover
    require_distinct_approvers_across_jurisdictions: true
charter:
  accounts:
    jurisdiction: "cloud/{account}"
    source_jurisdiction: "cloud/{account}/app/{project}"
    target_jurisdiction: "cloud/{account}/data/{tenancy}"
    ldap_groups:
      search_base: "ou=accounts,dc=corp,dc=internal"
      roles:
        - { group_dn: "cn=operators,ou={account},ou=accounts,dc=corp,dc=internal", role: operator, jurisdiction: "cloud/{account}/*" }
        - { group_dn: "cn=approvers,ou={account},ou=accounts,dc=corp,dc=internal", role: approver, jurisdiction: "cloud/{account}/*" }
        - { group_dn: "cn=approvers,ou={project},ou={account},ou=accounts,dc=corp,dc=internal", role: approver, jurisdiction: "cloud/{account}/app/{project}" }
  source_jurisdictions:
    - { trust_domain: cloud.internal, mode: path_template, path_regex: '^/acct/([a-z0-9]+)/project/([a-z0-9]+)/', jurisdiction_template: 'cloud/${1}/app/${2}' }
  interconnects:
    default_cross_jurisdiction: deny
    rules:
      - { name: accounts, from: ["cloud/*"], to: ["cloud/*"], action: allow }
```

Account, project and tenancy names are lower-case letters and digits, starting with a letter. A segment such as `fin-01` cannot be an account, and a jurisdiction using it under `jurisdiction` is refused, so keep existing jurisdictions outside this root. The `path_regex` above also lets through a name starting with a digit, because each group must be one character class repeated with `+`; such a jurisdiction is refused as no account can have that name.

Three things outside `ligo` become part of its security:

- **The directory.** Whoever can create groups or add members under an account's unit can grant `ligo` roles in that account. Restrict writing there as you restrict `server.yaml`. Only direct membership counts, and only for registered accounts.
- **SPIRE.** An account's isolation rests on who can register SPIFFE IDs under `/acct/<account>/`.
- **The secret store.** A binding using a store works only if the store accepts JWT-SVIDs of the source's trust domain. Keep accounts' SPIFFE IDs in the trust domain of the store's realm, or configure the store's JWT auth for theirs. `ligo` does not check this: the binding reaches `ACTIVE`, and the workload then fails when it reads its credential.

For a shared PostgreSQL, set `namespace_template` on the platform and use `grantable_role_templates`; see the chapter on plugins. For each tenancy, the platform team creates, outside `ligo`, the schema `<account>_<tenancy>`, its roles with `ADMIN OPTION` for the plugin's admin, and the privileges of those roles. `ligo` checks the names, not what the roles grant.

## Sealing and storage

```yaml
storage:
  postgres: { app_dsn_env: LIGO_PG_APP_DSN, reader_dsn_env: LIGO_PG_READER_DSN, dbos_dsn_env: LIGO_PG_DBOS_DSN }
secret_sealing:
  provider: vault-transit
  vault_transit:
    address: "https://vault.prod.internal:8200"
    auth_mount: jwt-spiffe
    role: ligo-sealer
    jwt_audience: "https://vault.prod.internal"
    mount: transit
    key_name: ligo-interstage
plugins:
  directory: "/usr/lib/ligo/plugins"
```

`vault_transit.jwt_audience` must be one of `core_identity.svid_selector.jwt_audience`. Never use the `local-kek` provider in production: it needs the `--insecure-dev` flag, and exists for development only.

## Starting it

```bash
sudo systemctl enable --now ligo
journalctl -u ligo -f
```

At startup `ligo` checks the configuration, connects to SPIRE and the sealer, verifies each plugin's owner, mode and hash, and starts each plugin. A failure names what is wrong and ends startup. The unit restarts it with a back-off; `systemctl status ligo` shows the last error.

| Flag of `ligo serve` | Use it |
| :-------------------- | :---------------------------------- |
| `--maintenance` | To start with changes refused, after a restore |
| `--allow-orphaned-bindings` | When a binding refers to an instance you removed on purpose; audited |
| `--accept-jurisdiction-changes` | When you changed a jurisdiction mapping on purpose, to transfer the resources; audited |
| `--insecure-dev` | Local development only |

## The client

The same binary is the client. It authenticates with an SVID from a Workload API socket, or with an LDAP user when `allow_basic_auth` is on:

```bash
ligo --server https://ligo-admin.corp.internal:9443 --spiffe-socket /run/spire/prod/agent.sock list bindings
```

Workloads and administrators verify `ligo`'s SVID against the socket's bundle; `--server-id` names the identity it must have, by default the core identity of the service. Use `--ca-cert` when the admin listener has a certificate from a file.
