# Troubleshooting

## `ligo` does not start

`systemctl status ligo` and `journalctl -u ligo` show the first error. Failures are fatal, name what is wrong, and write nothing. The unit keeps restarting with a back-off, so fixing the cause is enough.

| Log says | Check |
| :------------------------------- | :-------------------------------------- |
| An agent socket does not answer | The agent; the entry for this user; the socket's path |
| The sealer cannot be reached | Vault is up and unsealed; `ligo-sealer`; `vault_transit.ca_cert_file` |
| A plugin's checksum, owner or mode | `sha256` in `server.yaml` against `sha256sum`; `root:root`; no symlink |
| A plugin's config fails its schema | The instance and field it names |
| `instance "...": SVID` matched none or several | The plugin's SPIRE entry; run the binary with `-svids`, as the user `ligo` |
| A binding references a removed instance | Restore it, or give `--allow-orphaned-bindings` on purpose |
| Stored jurisdictions differ from the configuration | Restore the mapping, or give `--accept-jurisdiction-changes` on purpose |

## A plugin does not get its SVID

The entry selects on `unix:sha256`, and an upgrade changed the binary. Compare `sha256sum` with `spire-server entry show`, and remember that a new entry reaches the agent only at its next sync. The agents' `unix` attestor needs `discover_workload_path = true`.

## A workload gets no bindings

1. Is it the identity you expect? Print its SVID's URI SAN.
2. Does the source's regex match it? `ligo source test --trust-domain ... --regex ... --id <its SPIFFE ID>`.
3. Is the binding `ACTIVE`, with a snapshot? `ligo get binding <name>`. `PROVISIONING` with no earlier snapshot serves nothing yet.
4. Is its trust domain in `accepted_trust_domains`? Is the bundle current?
5. A `503` means fail closed: a bundle error, or the cache beyond `max_staleness`. Check the agent and PostgreSQL.

The API answers within `full_reload_interval` at worst, normally at once.

## A workload gets a binding, but its credential does not work

| Symptom | Likely cause |
| :------------------------------- | :-------------------------------------- |
| Vault login refused | The JWT-SVID's audience is not `workload_jwt_audience`; or its trust domain is not one this Vault trusts. A workload of another trust domain cannot log in unless Vault's JWT auth trusts its bundle |
| Password refused, right after a rotation | The window between Stage 2 and Stage 3: read the credential again and retry |
| `no pg_hba.conf entry` | The database's `pg_hba.conf` does not accept this user or network, or does not use TLS |
| `LDAP authentication failed` | With `openldap.v1`: `ldapprefix` and `ldapsuffix` against `service_ou_dn`; `TLS_CACERT` in `ldap.conf` on the PostgreSQL host |
| The admin role cannot log in, after adding LDAP | Holding `ADMIN` on the group makes it a member: its `scram-sha-256` line must come first |
| Permission denied on a table | The group role lacks the privilege. `ligo` grants the role, not the table |

## A change is refused

Run `ligo charter check -f <manifest>`: it shows the jurisdictions, the name prefix, the consent rule, the interconnection rule and the sides, without filing anything. Then see the *Error reference*.

## A binding is stuck

- **`PROVISIONING` for long.** Its replica may be down: `ligo executors list`. See *A replica died*.
- **Drift keeps returning.** Someone changes the role by hand. The reconciler repairs it; `ligo audit list` shows `REAPPLY_STARTED`.
- **`DELETE_FAILED`.** Read the code. `ROLE_OWNS_OBJECTS` is the usual one: reassign the objects, then `ligo retry`.

## The web UI

- **`403` on every form.** `external_origin` differs from the address in the browser, or a proxy strips `Origin`.
- **Login refused with the right password.** The per-user limit: `SESSION_LOGIN_FAILED` entries show who tried. Wait a minute.
- **A theme does not apply.** Theme files must be root-owned and pass their checks; a missing file is not an error, a bad one is, at startup.
