# The `openldap.v1` identity provider

This file specifies `ligo-plugin-openldap`, the external identity provider that manages one directory account per binding (§0.4, §5). It is the only shipped external plugin so far: the lab's `ligo-plugin-postgres` and `ligo-plugin-vault` stay test tooling. The rules of §5.8 apply; this file states only what they leave open.

Status: approved 2026-11-04, chunk plan at the end.

## 1. What it does

For each binding, Stage 1 creates an account in one organizational unit of an OpenLDAP directory, gives it a generated password and returns that password to the engine, which forwards it to Stage 3 (`EXTERNAL_DIR`, §5.6). A platform that authenticates its users against the same directory then accepts the credential the workload reads from the secret store.

Out of scope: `activedirectory.v1`; groups (`IdentityArtifact.groups` stays empty, and privileges are granted in Stage 2); password policy overlays; dual passwords. OI-2 (the example wires Oracle to this plugin) is unchanged.

## 2. Packaging

- Source in `cmd/plugins/ligo-plugin-openldap`, binary and package `ligo-plugin-openldap`, type `openldap.v1`, kind `IDENTITY_PROVIDER`, `produced_identity_mode = EXTERNAL_DIR`.
- It imports `pkg/pluginsdk` and the generated API only, never `test/`.
- It has its own deb, rpm and archive, built from the same repository, tag and version as `ligo`, and covered by the release's checksums. The package depends on `ligo`, with no version pin: startup checks the protocol through `Describe`.
- Layout:

| Path | Package |
| :--- | :--- |
| `/usr/bin/ligo` | `ligo` |
| `/usr/lib/ligo/plugins/` (`root:root`, `0755`) | both |
| `/usr/lib/ligo/plugins/ligo-plugin-openldap` (`root:root`, `0755`) | `ligo-plugin-openldap` |

- **Upgrades.** `plugins[].sha256` pins the binary, so a package update cannot silently change privileged code: after upgrading, the new binary is refused until the operator sets the new hash (`sha256sum /usr/lib/ligo/plugins/ligo-plugin-openldap`) in `server.yaml` and restarts or reloads `ligo`.

## 3. Instance configuration

`ConfigureInstances` refuses, with `INVALID_CONFIG` and naming the field, any value that breaks these rules. Unknown fields are refused too.

| Field | Required | Rule |
| :--- | :--- | :--- |
| `url` | yes | `ldaps://host[:port]` (port 636 by default). `ldap://` and StartTLS are refused: the plugin sends passwords. |
| `service_ou_dn` | yes | A valid DN (RFC 4514); the accounts' parent. |
| `allowed_endpoints` | yes | Must contain the `host:port` of `url` (§5.7's form). |
| `bootstrap_credential` | yes | §5.5, `kv_path` only. Its `username` is the bind DN and must be a valid DN. |
| `ca_file` | no | A PEM file of the roots that verify the directory; the system roots when absent. TLS 1.2 or later, hostname verified. |

An instance selects its SVID as §5.4 says, and reads its credential with it. The file is read once, at configuration.

## 4. The account

| Attribute | Value |
| :--- | :--- |
| DN | `uid=<principal>,<service_ou_dn>` |
| `objectClass` | `inetOrgPerson` (with `top`, `person`, `organizationalPerson`) |
| `uid`, `cn`, `sn` | `<principal>` |
| `description` | `ligo:binding_id=<uuid>` (§5.8 rule 2) |
| `userPassword` | Set only through the Password Modify extended operation (RFC 3062), so the directory hashes it |

- `<principal>` is `BindingContext.derived_principal_name`. It must match `^[a-z][a-z0-9_]{0,19}$` (`INVALID_PRINCIPAL`, terminal) and is the only request value in the DN (§5.8 rule 3). No LDAP filter is built from request values: entries are read by base-scope search on the DN, with the filter `(objectClass=*)`.
- `inetOrgPerson` has no mandatory password, so an account created by a crashed call has no password and nobody can bind to it. `simpleSecurityObject` would require sending the password in the `Add`, and a directory without a hashing overlay would store it in clear.
- The account is ours only if one `description` value equals the tag exactly. An untagged entry is foreign.

## 5. RPCs

**`EnsureIdentity`**

| The entry at the DN | `rotate_static_secrets` | Result |
| :--- | :--- | :--- |
| absent | any | `Add`, Password Modify with a new password, return the secret |
| ours | true | Password Modify with a new password, return the secret |
| ours | false | Nothing changes; `secret_unchanged = true`, no secret (§5.8 rule 4) |
| foreign | any | `FAILED_PRECONDITION`, `RESOURCE_OWNED_BY_OTHER_BINDING` |

- The artifact has `mode = EXTERNAL_DIR`, `principal_id = <principal>`, `distinguished_name = <DN>`, and, when a secret is returned, `static_secret` with `username = <principal>` and the password. Nothing else.
- Passwords come from `pluginsdk.GeneratePassword`, 40 characters (§5.8 rule 3).
- An `Add` that finds the entry already there (a concurrent or retried call) reads it again and follows the table once.
- A retry after a crash between `Add` and Password Modify finds the entry ours with `rotate_static_secrets` still true, as the attempt that created it had it (§6.4), and sets the password.

**`CleanupIdentity`**: absent succeeds; ours is deleted; foreign is left, with `skipped_not_owner = true`. It does not use `previous_artifact`, which may be empty (AC-10).

**`Health`**: for the named instance, a TLS connection and a bind with the bootstrap credential. `Serving = false` with a generic message otherwise.

**Connections.** One connection per call, with a 10 s timeout, closed at the end of the call. No pool: calls are rare, and each one reads the current credential.

## 6. Errors

`public_message` is fixed for each code: directory diagnostics are never copied to it or logged, as they can echo request data (§5.8 rules 5 and 6).

| Condition | gRPC code | `code` | Retryable |
| :--- | :--- | :--- | :--- |
| Network or TLS failure, LDAP `busy` (51), `unavailable` (52) | `UNAVAILABLE` | `DIRECTORY_UNAVAILABLE` | yes |
| Credential cannot be read | `UNAVAILABLE` | `BOOTSTRAP_CREDENTIAL_UNAVAILABLE` | yes |
| LDAP `invalidCredentials` (49) | `UNAVAILABLE` | `BOOTSTRAP_CREDENTIAL_REJECTED` | yes: the credential may be mid-rotation |
| LDAP `insufficientAccessRights` (50) | `PERMISSION_DENIED` | `DIRECTORY_ACCESS_DENIED` | no |
| `noSuchObject` (32) on the OU, or any other LDAP refusal | `FAILED_PRECONDITION` | `DIRECTORY_REJECTED` | no |

## 7. Known limits

- **Rotation window.** OpenLDAP has one password per account: between Stage 1 changing it and Stage 3 storing it, the workload's stored credential does not bind (R-03). It lasts as long as those two stages.
- **Password policy.** A directory policy that refuses a generated password surfaces as `DIRECTORY_REJECTED`.
- **Hashing is the directory's.** `olcPasswordHash` decides the scheme; the plugin cannot check it.

## 8. Acceptance

| ID | Given | When | Then | Level |
| :--- | :--- | :--- | :--- | :--- |
| OL-1 | An invalid `url` (`ldap://`), DN, endpoint list or unknown field | `ConfigureInstances` | `INVALID_CONFIG` naming the field | U |
| OL-2 | No account | `EnsureIdentity` | The account of §4 exists; the returned password binds; `userPassword` is stored hashed | P |
| OL-3 | An account of this binding | `EnsureIdentity` without rotation, twice | No secret, `secret_unchanged`; the old password still binds | P |
| OL-4 | An account of this binding | `EnsureIdentity` with rotation | A new password binds; the old one does not | P |
| OL-5 | An account tagged with another binding, or untagged | `EnsureIdentity`; `CleanupIdentity` | `RESOURCE_OWNED_BY_OTHER_BINDING`; `skipped_not_owner`; the entry is untouched | P |
| OL-6 | An account created with no password | `EnsureIdentity` with rotation | The password is set | P |
| OL-7 | A principal outside the grammar, with DN metacharacters | `EnsureIdentity` | `INVALID_PRINCIPAL`; no request reaches the directory | U |
| OL-8 | An account; then none | `CleanupIdentity` twice, the first with an empty artifact | Removed; the second succeeds | P |
| OL-9 | The directory stopped, or the bind DN's password changed | `EnsureIdentity`; `Health` | The retryable codes of §6; not serving; the message has no secret and no diagnostic | P |
| OL-10 | Each LDAP result code of §6 | Mapping | The code and the retryability of §6 | U |
| OL-11 | A platform wired to `openldap.v1` and `vault-static` on the lab | A binding is approved | `ACTIVE`; the credential read from the store connects to PostgreSQL, which verifies it against the directory | L |
| OL-12 | That binding | Rotated | The old credential stops connecting; the new one connects | L |
| OL-13 | That binding | Revoked | The account is gone; the credential no longer connects; `DELETE_COMPLETED` | L |
| AC-10 | Stage 2 fails terminally after Stage 1 created the account | The binding is deleted | `TARGET` cleaned with its empty artifact, the LDAP account removed, the row gone | L |
| OL-14 | After OL-11 to OL-13 | The tables, DBOS checkpoints and logs of `ligo` and of the plugin are searched for the passwords | Not found (INV-03) | L |

## 9. Lab

- `ou=ligo-accounts` and the service account `cn=ligo-idp` already exist, with their access rules (`test/lab/lib/ldap.sh`).
- New: SPIRE entry `spiffe://prod.lab/ligo/plugin/openldap`, an OpenBao and Vault role, and the KV secret with `cn=ligo-idp`'s DN and password.
- The lab's `ligo-plugin-postgres` also accepts `EXTERNAL_DIR`: it creates the role with no password and tagged, and grants as usual. `pg_hba` verifies members of a new group role `ligo_ldap` with `ldap ldapscheme=ldaps`, `ldapprefix="uid="` and `ldapsuffix=",ou=ligo-accounts,dc=ligo,dc=lab"`.
- A new platform `pg-ledger-ldap` uses them, beside `pg-ledger`, whose tests do not change.

## 10. Chunks

Each is tests first, then code, with the usual checks; each ends in its own commit after approval.

1. **Spec**: this file, its pointer in §5.1.
2. **Plugin**: `cmd/plugins/ligo-plugin-openldap`, with the directory behind a small interface; unit tests for OL-1, OL-7, OL-10 and the table of §5.
3. **Real directory**: `deploy.sh` builds and registers it; `TestLabIdentityOpenLDAP` for OL-2 to OL-6, OL-8, OL-9.
4. **End to end**: `ligo-plugin-postgres` and `pg_hba`, the platform, and `lab.sh serve test` for OL-11 to OL-14 and AC-10; on OpenBao, then on Vault.
5. **Documentation and packaging**: the second build, archive and package in `.goreleaser.yaml`, with `ligo` also packaged to the layout of §2, `examples/server.yaml` and §8.1 (`ca_file`), a plugin section in the operator documentation, `.specs/ligo-test-environment.md`, and the matrix's AC-10.
