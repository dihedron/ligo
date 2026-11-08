# The plugins

Each plugin is declared with its binary and its hash. `ligo` runs one process per plugin type and realm, and refuses a binary whose hash differs, before every start.

## The Vault store

```yaml
secret_stores:
  - type: "vault.v1"
    binary: "ligo-plugin-vault"
    sha256: "<its hash>"
    instances:
      - name: "vault-prod"
        realm: prod
        svid_selector:
          match_expr: 'path == "/ligo/plugin/vault"'
          jwt_audience: ["https://vault.prod.internal"]
        config:
          address: "https://vault.prod.internal:8200"
          allowed_endpoints: ["vault.prod.internal:8200"]
          auth_mount: "jwt-spiffe"
          role: "ligo-plugin-vault"
          workload_jwt_audience: "https://vault.prod.internal"
        network_flows:
          - { name: vault, purpose: CREDENTIALS, protocol: TCP, destination: "vault.prod.internal", ports: [8200], tls: true, server_name: "vault.prod.internal" }
```

## The PostgreSQL provider

A platform is one database of one server. The operator of that database first prepares:

- the **group roles** that access levels will grant, already holding their privileges on the schemas: `ligo` never creates schemas, tables or those roles;
- an **admin role** for the plugin: not a superuser, with `CREATEROLE`, `ADMIN OPTION` on each of those roles, `CONNECT` on the database, and membership of `pg_signal_backend`, so that it can end a revoked role's sessions.

```sql
CREATE ROLE ligo_target_admin LOGIN CREATEROLE PASSWORD '...';
GRANT "LEDGER_RO_ROLE", "LEDGER_RW_ROLE" TO ligo_target_admin WITH ADMIN OPTION;
GRANT pg_signal_backend TO ligo_target_admin;
GRANT CONNECT ON DATABASE ledger TO ligo_target_admin, "LEDGER_RO_ROLE", "LEDGER_RW_ROLE";
```

Let `pg_hba.conf` accept any role over `hostssl` with `scram-sha-256` on that database, from where workloads and the plugin connect. Then:

```yaml
identity_providers:
  - { type: target-local.v1, builtin: true, instances: [ { name: local-prod, realm: prod } ] }
platform_providers:
  - type: "postgres.v1"
    binary: "ligo-plugin-postgres"
    sha256: "<its hash>"
    platforms:
      - name: pg-ledger
        realm: prod
        jurisdiction: "dc/corp-prod"
        display_name: "Ledger database"
        allowed_source_trust_domains: [prod.internal]
        network_flows:
          - { name: postgres, purpose: DATA, protocol: TCP, destination: "db.prod.internal", ports: [5432], tls: true, server_name: "db.prod.internal" }
        identity_provider: { type: target-local.v1, instance: local-prod }
        secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-static }
        svid_selector:
          match_expr: 'path == "/ligo/plugin/postgres"'
          jwt_audience: ["https://vault.prod.internal"]
        config:
          host: db.prod.internal
          port: 5432
          database: ledger
          grantable_roles: [LEDGER_RO_ROLE, LEDGER_RW_ROLE]
          allowed_endpoints: ["db.prod.internal:5432"]
          bootstrap_credential:
            source: vault
            address: "https://vault.prod.internal:8200"
            auth_mount: jwt-spiffe
            role: ligo-plugin-postgres
            jwt_audience: "https://vault.prod.internal"
            kv_path: kv/data/ligo/bootstrap/postgres
```

`grantable_roles` is the privilege bound: no target or binding can grant anything outside it, and tightening it takes effect even for levels published earlier. On a platform with a `namespace_template`, use `grantable_role_templates: ["{namespace}_read", "{namespace}_write"]` instead, so that a target can only offer the roles of its own schema; `{namespace}` stands for the schema, and the admin role needs `ADMIN OPTION` on each role when the schema is created. `grantable_roles` beside it are shared across tenants, and startup warns of them. Startup also warns of templates on a platform with no `namespace_template`: an operator then picks the schema, and so any tenant's role. Two platforms on one plugin share its SVID: set `allow_shared_svid: true` on both selectors.

`bootstrap_credential.jwt_audience` must be listed in the same instance's `svid_selector.jwt_audience`.

## Credentials on demand

To let Vault's database engine make a short-lived credential per workload, wire the platform like this, and set the store's `db_connection`:

```yaml
identity_provider: { type: delegated-dynamic.v1, instance: dynamic-prod }
secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-dynamic }
```

## The OpenLDAP provider

It creates one account per binding in one organizational unit, and PostgreSQL verifies it against the directory.

1. Serve the directory over `ldaps://`. The plugin refuses `ldap://` and StartTLS, because it sends passwords.
2. Create the unit, for example `ou=ligo-accounts,dc=prod,dc=internal`, and a service account limited to it:

   ```ldif
   olcAccess: to attrs=userPassword by dn.exact="cn=ligo-idp,ou=services,dc=prod,dc=internal" write by self write by anonymous auth by * none
   olcAccess: to dn.subtree="ou=ligo-accounts,dc=prod,dc=internal" by dn.exact="cn=ligo-idp,ou=services,dc=prod,dc=internal" write by users read by * none
   ```

3. Set `olcPasswordHash` to the scheme you want. The plugin sets passwords with the Password Modify operation, so the directory hashes them, and it cannot check which scheme is used.
4. In PostgreSQL, create a group role for these accounts, and give the plugin's admin `ADMIN OPTION` on it. **Holding `ADMIN` makes the admin count as a member**, so its own line must come first in `pg_hba.conf`, as the first match wins:

   ```text
   hostssl ledger ligo_target_admin 10.0.0.0/8 scram-sha-256
   hostssl ledger +ligo_ldap 10.0.0.0/8 ldap ldapserver=openldap.prod.internal ldapscheme=ldaps ldapprefix="uid=" ldapsuffix=",ou=ligo-accounts,dc=prod,dc=internal"
   hostssl ledger all 10.0.0.0/8 scram-sha-256
   ```

   PostgreSQL's LDAP client reads its CA from `TLS_CACERT` in `/etc/ldap/ldap.conf`.

```yaml
identity_providers:
  - type: "openldap.v1"
    binary: "ligo-plugin-openldap"
    sha256: "<its hash>"
    instances:
      - name: "ldap-prod"
        realm: prod
        svid_selector:
          match_expr: 'path == "/ligo/plugin/openldap"'
          jwt_audience: ["https://vault.prod.internal"]
        config:
          url: "ldaps://openldap.prod.internal:636"
          service_ou_dn: "ou=ligo-accounts,dc=prod,dc=internal"
          allowed_endpoints: ["openldap.prod.internal:636"]
          bootstrap_credential:
            source: vault
            address: "https://vault.prod.internal:8200"
            auth_mount: "jwt-spiffe"
            role: "ligo-plugin-openldap"
            jwt_audience: "https://vault.prod.internal"
            kv_path: "kv/data/ligo/bootstrap/openldap"
```

On the platform, set `directory_group: ligo_ldap` in the PostgreSQL provider's `config`, and wire `identity_provider: { type: openldap.v1, instance: ldap-prod }`.
