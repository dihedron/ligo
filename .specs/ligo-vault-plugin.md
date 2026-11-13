# The `vault.v1` secret store

This file specifies `ligo-plugin-vault`, the external secret store that keeps a binding's credential in Vault or OpenBao, and lets only that binding's workload read it. The rules of §5.8 apply; this file states only what they leave open.

Status: approved 2026-11-05.

## 1. What it does

For each binding, Stage 3 keeps a secret or a database role, a policy that reads only it, and a JWT role that gives that policy only to the binding's workload. Without this store, the `TARGET_LOCAL`, `EXTERNAL_DIR` and `DELEGATED_DYNAMIC` modes have nowhere to deliver a credential (§5.6).

## 2. Packaging

As `.specs/ligo-openldap-plugin.md` §2: source in `cmd/plugins/ligo-plugin-vault`, binary and package `ligo-plugin-vault`, in `/usr/lib/ligo/plugins`; the package depends on `ligo`, with no version pin. It imports `pkg/pluginsdk` and the generated API only, never `test/`.

## 3. Instance configuration

`ConfigureInstances` refuses with `INVALID_CONFIG`, naming the field, any value that breaks these rules. Unknown fields are refused too.

| Field | Required | Rule |
| :--- | :--- | :--- |
| `address` | yes | `https://host[:port]`, port 443 by default. |
| `allowed_endpoints` | yes | Must contain the `host:port` of `address`. |
| `auth_mount` | yes | The JWT auth mount, for the plugin and for workloads. |
| `role` | yes | The plugin's own JWT role. |
| `workload_jwt_audience` | yes | The audience of workloads' JWT-SVIDs for their per-binding roles. |
| `kv_mount` | no | A KV v2 mount; default `kv`. |
| `namespace` | no | A Vault Enterprise namespace, sent with every request. |
| `database_mount` | no | The database secrets engine; default `database`. |
| `db_connection` | with `vault-dynamic` | The engine's connection to the target. Without it, `vault-dynamic` is `DB_CONNECTION_NOT_CONFIGURED`, and cleanup does not touch the engine, so a static-only deployment needs no rights on it. |
| `ca_pem` | no | PEM text (not a file path, ligo-instances T-22d) of the roots that verify `address`; the system roots when absent. |

A mount matches `^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`.

## 4. Who may read: exact SPIFFE IDs only

This settles OI-1. A JWT role binds a subject exactly or by glob, and Vault's glob `*` also matches `/`, so a glob could release a credential to a workload that `ligo` rejects. The store therefore binds **one exact SPIFFE ID**.

- A source's regex qualifies when it matches exactly one SPIFFE ID: `^spiffe://…$`, with escaped dots and no other metacharacter (`pluginsdk.LiteralSPIFFEID`).
- The store declares `subject_match = SUBJECT_MATCH_EXACT` on both its strategies (§5.6). `ligo` refuses a binding whose source does not qualify when it is filed: `422 source-not-exact`. A source can only narrow, so a qualifying source stays so.
- The plugin checks again in `EnsureSecretStore`: `SOURCE_NOT_EXACT`, terminal.

**Known limit.** A source covering many workloads, such as `w-[0-9]+`, cannot use this store. Register a source per workload.

## 5. Objects, per binding

`<id>` is the binding's UUID, the only request value in a path; it is checked first.

| Object | Path | Strategy |
| :--- | :--- | :--- |
| Secret, with `username` and `password` | `<kv_mount>/data/bindings/<id>`; custom metadata `ligo_binding_id`; `max_versions = 1`, so that an old password does not linger | `vault-static` |
| Database role | `<database_mount>/roles/binding-<id>` | `vault-dynamic` |
| Policy reading that path only | `sys/policies/acl/binding-<id>` | both |
| JWT role: `bound_subject`, `bound_audiences`, that policy | `auth/<auth_mount>/role/binding-<id>` | both |

The finalized client auth gives `address`, `audience` (the instance's `workload_jwt_audience`, for the workload's JWT-SVID), `authMount`, `role`, `policy`, and `secretPath` or `credsPath`.

## 6. RPCs

**`EnsureSecretStore`** converges those objects. With `secret_unchanged`, the stored secret is left alone and the rest converges.

**`CleanupSecretStore`** revokes the role's leases and deletes the objects; what is absent is success.

**`Health`**: a login with the plugin's JWT-SVID. `Serving = false` with a fixed message otherwise.

**Tokens.** Each call logs in with the instance's JWT-SVID and revokes its token at the end, whatever the outcome. A token that cannot be revoked expires by its TTL.

**`-svids SOCKET`**: as `openldap.v1`.

**`version [-v]`**: as `openldap.v1`.

## 7. What the plugin's role may do

The operator gives the plugin's JWT role a policy that allows, and only allows:

```hcl
path "<kv_mount>/data/bindings/*"     { capabilities = ["create", "update", "read"] }
path "<kv_mount>/metadata/bindings/*" { capabilities = ["create", "update", "read", "delete"] }
path "sys/policies/acl/binding-*"     { capabilities = ["create", "update", "read", "delete"] }
path "auth/<auth_mount>/role/binding-*" {
  capabilities = ["create", "update", "read", "delete"]
  allowed_parameters = {
    "token_policies" = ["binding-*"]
    "*" = []
  }
}
```

With `vault-dynamic`, also: `<database_mount>/roles/binding-*` (the same capabilities) and `sys/leases/revoke-prefix/<database_mount>/creds/binding-*` (`update`, `sudo`).

`allowed_parameters` stops a compromised plugin giving a workload any other policy, as `binding-*` is the only form its roles can carry.

## 8. Errors

Messages are fixed; only the method, path and status are logged, never a response body.

| Condition | gRPC code | `code` | Retryable |
| :--- | :--- | :--- | :--- |
| Network or TLS failure, `429`, `5xx` (a sealed server is `503`) | `UNAVAILABLE` | `VAULT_UNAVAILABLE` | yes |
| The SVID cannot be fetched | `UNAVAILABLE` | `SVID_UNAVAILABLE` | yes |
| `403` | `PERMISSION_DENIED` | `VAULT_ACCESS_DENIED` | no |
| Any other refusal | `FAILED_PRECONDITION` | `VAULT_REJECTED` | no |
| A payload that does not fit the strategy | `FAILED_PRECONDITION` | `INCOMPATIBLE_IDENTITY_MODE` | no |
| An unknown strategy | `FAILED_PRECONDITION` | `UNKNOWN_STRATEGY` | no |

## 9. Acceptance

| ID | Given | When | Then | Level |
| :--- | :--- | :--- | :--- | :--- |
| VS-1 | A bad address, mount, endpoint list or unknown field; `http://` | `ConfigureInstances` | `INVALID_CONFIG` naming the field | U |
| VS-2 | A binding ID outside the grammar, or a regex that is not one SPIFFE ID | `EnsureSecretStore` | `INVALID_BINDING`; `SOURCE_NOT_EXACT`; nothing is written | U |
| VS-3 | A static payload | `EnsureSecretStore` | The objects of §5, with custom mounts and namespace | U |
| VS-4 | `secret_unchanged` | `EnsureSecretStore` | The secret is not written; the rest converges | U |
| VS-5 | A delegated role | `EnsureSecretStore` | The database role, the policy, and a JWT role for the workload | U |
| VS-6 | Each status of §8 | Mapping | The code and retryability of §8 | U |
| VS-7 | Any call | It ends | The token is revoked | U |
| VS-8 | A source that is not exact, on a platform with this store | The binding is filed | `422 source-not-exact` | I |
| VS-9 | A static-only instance | `CleanupSecretStore` | The engine is not touched | U |
| VS-10 | The plugin on the lab | The suites of `lab.sh serve test`, a workload logging in with its own role in both strategies | Pass, on OpenBao and Vault | L |
