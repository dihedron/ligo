# The `postgres.v1` platform provider

This file specifies `ligo-plugin-postgres`, the external platform provider that manages one PostgreSQL role per binding. The rules of §5.8 apply; this file states only what they leave open.

Status: approved 2026-11-05.

## 1. What it does

A platform is one database of one PostgreSQL server. For each binding, Stage 2 creates a role tagged with the binding, and makes it a member of exactly the roles of the access level. A target is a schema of that database; its access levels name roles that the database's owner has already created and granted privileges to. The plugin never creates schemas, tables or those roles (ADR-15).

## 2. Packaging

As `.specs/ligo-openldap-plugin.md` §2: source in `cmd/plugins/ligo-plugin-postgres`, binary and package `ligo-plugin-postgres`, in `/usr/lib/ligo/plugins`; the package depends on `ligo`, with no version pin. It imports `pkg/pluginsdk` and the generated API only, never `test/`.

## 3. Instance configuration

`ConfigureInstances` refuses with `INVALID_CONFIG`, naming the field, any value that breaks these rules. Unknown fields are refused too.

| Field | Required | Rule |
| :--- | :--- | :--- |
| `host` | yes | The server's name, verified against its certificate. |
| `port` | yes | 1 to 65535. |
| `database` | yes | An identifier (§4). |
| `grantable_roles` | one of these two | Identifiers: the privilege bounds, deliberately shared roles on a namespaced platform. |
| `grantable_role_templates` | one of these two | Each an identifier once `{namespace}`, held exactly once, is replaced by the target's schema: the bounds of that target (.specs/ligo-tenancy.md §6). |
| `allowed_endpoints` | yes | Must contain `host:port`. |
| `bootstrap_credential` | yes | §5.5, `kv_path` only. Its `username` is the admin role of §5. |
| `ca_pem` | no | PEM text (not a file path, ligo-instances T-22d) of the roots that verify the server and the Vault of `bootstrap_credential`; the system roots when absent. |
| `credential_ttl` | no | With `DELEGATED_DYNAMIC`: the lease of each credential the store issues, a duration (`90s`, `15m`). When absent, `ligo`'s `plugins.dynamic_credentials.default_ttl`. |
| `credential_max_ttl` | no | With `DELEGATED_DYNAMIC`: the longest a lease may be renewed to. When absent, `plugins.dynamic_credentials.max_ttl`. |
| `directory_group` | with `EXTERNAL_DIR` | An identifier: a group role of which every directory-verified role is made a member, so that one `pg_hba.conf` line, `+directory_group`, covers them. |

Connections always use `sslmode=verify-full`, with a 10 s connection timeout, one per call.

**The lease of a dynamic credential.** Each of the two values is resolved by itself, the first that is set winning:

1. the platform's `credential_ttl` or `credential_max_ttl`;
2. `plugins.dynamic_credentials.default_ttl` or `max_ttl` in `server.yaml`;
3. the built-in 1 h and 24 h.

- The plugin sends the platform's values in the role it hands to the store, and 0 for a value the platform does not set. The engine fills a 0 from `server.yaml` or the built-in value before the store stage, so the rule holds for any platform plugin.
- Each value is between 1 minute and 720 hours, checked when the platform is filed and when `server.yaml` is loaded. The global value is a default, not a cap: a platform may set a longer lease.
- The resolved lease must not exceed the resolved maximum. A platform whose `credential_ttl` is above the maximum in force fails the apply with `INVALID_CREDENTIAL_TTL`, not retryable.
- A change reaches a binding at its next apply or reconciliation. Leases already issued keep their time.

## 4. Identifiers and the definition

Identifiers match `^[A-Za-z_][A-Za-z0-9_]{0,62}$` and are always quoted. A principal matches `^[A-Za-z][A-Za-z0-9_]{0,62}$`, a binding ID must be a UUID, as it reaches a `COMMENT`. Anything else is refused before any statement runs.

- **Definition**: `{"database": <the instance's>, "schema": <identifier>}`.
- **Level grants**: `{"roles": [<identifiers within the bounds on this schema>]}`. Privileges are `role:<name>`, sorted, without duplicates.
- **Binding parameters**: `{"connectionLimit": 0..1000}`, 0 meaning no limit. They never add privilege.
- **`GetUISchemas`** gives the forms for these three, with `grantable_roles` and the templates, placeholder included, as the options of `roles`.

## 5. The admin role

The bootstrap credential names a role of the operator's that has:

- `CREATEROLE`, and `ADMIN OPTION` on every `grantable_roles` entry, every role expanded from `grantable_role_templates`, and `directory_group`;
- `CONNECT` on the database;
- membership of `pg_signal_backend`, to end a revoked role's sessions.

It is not a superuser. If it also holds `ADMIN` on `directory_group`, it counts as a member, so a `scram-sha-256` line for it must come before the group's line in `pg_hba.conf`: the first match wins.

## 6. RPCs

**`EnsureTarget`** runs in one transaction: a crash cannot leave a role without its tag, which would look foreign for ever.

| Identity mode | The role | `secret_unchanged` |
| :--- | :--- | :--- |
| `TARGET_LOCAL` | `LOGIN`, with a password when it is new or `rotate_static_secrets` is set | when not rotated |
| `EXTERNAL_DIR` | `LOGIN`, no password, also a member of `directory_group` | not applicable |
| `DELEGATED_DYNAMIC` | `NOLOGIN`, the parent of the users Vault creates, `IN ROLE` it | not applicable |

- A role tagged with another binding, or untagged, is `RESOURCE_OWNED_BY_OTHER_BINDING`. Memberships are made exactly the level's.
- **Passwords never travel in clear.** The plugin computes the SCRAM-SHA-256 verifier itself (4096 iterations, 16 random bytes of salt) and sends that, so a statement log holds no password. Passwords are 32 characters or more, as `password_length` says.
- `SVID` mode is refused: §10.

**`CleanupTarget`**: an absent role succeeds; a foreign one is left, with `skipped_not_owner`. Otherwise it ends the role's sessions with `pg_terminate_backend`, then drops the role, so that access ends when the revocation does. A role that owns objects cannot be dropped: `ROLE_OWNS_OBJECTS`, terminal, until the operator reassigns them.

**`Health`**: a connection and `SELECT 1`. `Serving = false` with a fixed message otherwise.

**`-svids SOCKET`**: as `openldap.v1`.

**`version [-v]`**: as `openldap.v1`.

## 7. Errors

Messages are fixed. PostgreSQL's text can echo a statement, so only the SQLSTATE is logged.

| Condition | SQLSTATE | gRPC code | `code` | Retryable |
| :--- | :--- | :--- | :--- | :--- |
| Credential cannot be read | | `UNAVAILABLE` | `BOOTSTRAP_CREDENTIAL_UNAVAILABLE` | yes |
| Credential refused | `28P01`, `28000` | `UNAVAILABLE` | `BOOTSTRAP_CREDENTIAL_REJECTED` | yes: it may be mid-rotation |
| Network, TLS or server going away | none, `08***`, `57P0*`, `53***` | `UNAVAILABLE` | `TARGET_UNAVAILABLE` | yes |
| Concurrent change | `40***`, `55***`, `42710`, `23505` | `UNAVAILABLE` | `TARGET_BUSY` | yes |
| A granted role does not exist | `42704` | `FAILED_PRECONDITION` | `ROLE_NOT_FOUND` | no |
| The admin may not do this | `42501` | `PERMISSION_DENIED` | `TARGET_ACCESS_DENIED` | no |
| The role owns objects | `2BP01` | `FAILED_PRECONDITION` | `ROLE_OWNS_OBJECTS` | no |
| Any other refusal | | `FAILED_PRECONDITION` | `TARGET_REJECTED` | no |

## 8. Known limits

- **Rotation window.** PostgreSQL has one password per role: between Stage 2 changing it and Stage 3 storing it, the stored credential does not connect (R-03).
- **Existing sessions** survive a rotation or a change of level, whose lost memberships apply to them at once. Only a revocation ends them.

## 9. Acceptance

| ID | Given | When | Then | Level |
| :--- | :--- | :--- | :--- | :--- |
| PG-1 | A bad host, port, identifier, endpoint list or unknown field; `EXTERNAL_DIR` with no group | `ConfigureInstances` | `INVALID_CONFIG` naming the field | U |
| PG-2 | A role outside `grantable_roles` and the templates expanded with the schema, or a bad definition | `ValidateTarget`, `ValidateBinding` | Refused; no statement | U |
| PG-3 | A principal or binding ID outside the grammar | Either RPC | `INVALID_*`; no statement | U |
| PG-4 | No role | `EnsureTarget`, `TARGET_LOCAL` | The password connects; the catalog holds a SCRAM verifier | I |
| PG-5 | The role | `EnsureTarget`, not rotated; rotated | No secret, the old password connects; a new one connects, the old does not | I |
| PG-6 | The role, a level with other roles | `EnsureTarget` | Memberships are exactly the level's | I |
| PG-7 | A foreign or untagged role | `EnsureTarget`; `CleanupTarget` | `RESOURCE_OWNED_BY_OTHER_BINDING`; `skipped_not_owner`; untouched | I |
| PG-8 | A statement fails after `CREATE ROLE` | `EnsureTarget` | No role is left | I |
| PG-9 | A role with an open session | `CleanupTarget` twice | The session ends, the role is gone; the second succeeds | I |
| PG-10 | A role owning a table | `CleanupTarget` | `ROLE_OWNS_OBJECTS`, not retryable | I |
| PG-11 | Each SQLSTATE of §7 | Mapping | The code and retryability of §7 | U |
| PG-12 | The server unreachable | `Health` | Not serving, with the fixed message | U |
| PG-13 | The plugin on the lab | The suites of `lab.sh serve test` | Pass over TLS, on OpenBao and Vault | L |

## 10. `SVID` mode, for after v0.1.0

This settles OI-4. It is not implemented: `accepted_identity_modes` leaves `SVID` out, so §8.2 rule 3 refuses `svid.v1` on a PostgreSQL platform.

**Why not `cert` authentication.** PostgreSQL's `cert` reads the subject's CN or DN, never the URI SAN that holds the SPIFFE ID. A CN set through a SPIRE entry's DNS name would make PostgreSQL trust a name outside `ligo`'s control: anyone able to register an entry with that name becomes that role, and the source's regex would not be enforced at the database.

**The design to build.** A JWT-SVID, through PostgreSQL 18's OAuth support (`OAUTHBEARER`):

1. **A validator module**, loaded by the server (`oauth_validator_libraries`), verifies the token against the trust domain's bundle, checks its audience and expiry, and gives its `sub` as the authenticated identity.
2. **The mapping.** `EnsureTarget` creates the role with `LOGIN` and no password, tagged as usual, and records in a table of the validator's that the role accepts `source_svid_regex`, so that the regex is enforced at the database. The validator refuses a `sub` the connecting role's regex does not match.
3. **`pg_hba.conf`**: `hostssl <database> +<group> oauth issuer=... scope=... validator=...`.
4. **Bundles.** The validator reads each trust domain's bundle from SPIRE's OIDC discovery provider, so that rotation needs no operator.
5. **Clients** present the token through libpq's `oauth_bearer`-style hook; each driver's support must be checked first, as this decides whether the feature is usable.
6. **The plugin** then accepts `SVID`, with `none.v1` as the store, and returns the endpoint, database and `user`. `client_output_schema_json` gains the token's audience.

Open before building: the validator's language (it is a server-side shared library in C), its packaging per PostgreSQL version, and client support in `pgx` and JDBC.
