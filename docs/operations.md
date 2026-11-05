# Operating ligo

This guide is for the people who install and run `ligo`. The rules behind each step are in [the specification](../.specs/ligo_specification.md).

## Install

`ligo` needs PostgreSQL, a SPIRE agent per zone on its host, and Vault or OpenBao with Transit for sealing.

1. Verify and install the package (README, *Verify a release*). It creates the system user `ligo`, the directory `/etc/ligo` (`root:ligo`, `0750`) and the unit `ligo.service`, which it neither enables nor starts.
2. Create the database and its roles once, as a superuser, with `/usr/share/ligo/examples/roles.sql`. Keep `ligo`'s connections off any pooler that hides `application_name`: recovery of a lost replica relies on it.
3. Write `/etc/ligo/server.yaml` (`root:ligo`, `0640`), starting from `/usr/share/ligo/examples/server.yaml`.
4. Write `/etc/ligo/ligo.env` (`root:ligo`, `0640`) with the DSNs and secrets that `server.yaml` names by environment variable, and `LIGO_INSTANCE_ID`, the replica's own stable ID.
5. Apply the migrations as `ligo_migrator`, with `ligo migrate`.
6. Start it: `systemctl enable --now ligo`.

The unit restarts `ligo` with a back-off while a dependency, such as a sealed OpenBao, keeps it down.

## Run

- **Reload.** `systemctl reload ligo` reloads certificate files only. Any other change to `server.yaml` needs a rolling restart.
- **Replicas.** Replicas share one database. A replica that dies must come back under the same `LIGO_INSTANCE_ID`, because only then do its workflows resume. Until then, its bindings stay `PROVISIONING` or `DELETING`, and resolution keeps serving what they last had.
- **A replica gone for good.** First confirm that the host is down, as the check on live sessions is evidence, not proof. Then run `ligo executors recover <id>`.
- **Metrics.** Prometheus metrics are on `server.metrics_listener`, by default `127.0.0.1:9090`.

## Upgrade

Migrations are forward-only.

1. `ligo maintenance on -m "upgrade to <version>"`
2. `ligo maintenance status --wait-drained`, which waits until nothing is in flight.
3. `ligo migrate`, as `ligo_migrator`, with the new binary.
4. Roll out the new version, one replica at a time.
5. `ligo maintenance off`

The workload API and all reads keep serving during maintenance.

## Back up and restore

The schemas `public` and `dbos` live in one database and must be backed up together, with point-in-time recovery. After a restore:

1. Start `ligo` with `--maintenance`.
2. Run `ligo maintenance status --wait-drained`, so that the sweeper settles the bindings.
3. Run `UPDATE bindings SET last_rotated_at = NULL`, so that every static secret is due for rotation.
4. Run `ligo maintenance off`. The next reconcile run rotates them.

## The `openldap.v1` identity provider

Its rules are in [its specification](../.specs/ligo-openldap-plugin.md). `ligo-plugin-openldap` creates one account per binding in an organizational unit of an OpenLDAP directory, and gives it a generated password. The password reaches the workload through the secret store, and a platform that authenticates its users against the same directory accepts it.

### Install

The plugin has its own deb, rpm and archive, published with each `ligo` release and listed in its checksums file. The package depends on `ligo`.

```bash
apt install ./ligo_<version>_linux_amd64.deb ./ligo-plugin-openldap_<version>_linux_amd64.deb
```

The binary is `/usr/lib/ligo/plugins/ligo-plugin-openldap`. `ligo` refuses it unless the directory and the binary are owned by `root:root`, and are not writable by anyone else, so install the archive's binary with the same owner and mode (`0755`).

### Prepare the directory

1. Serve the directory over `ldaps://`. The plugin refuses `ldap://` and StartTLS, because it sends passwords.
2. Create the organizational unit that will hold the accounts, for example `ou=ligo-accounts,dc=prod,dc=internal`.
3. Create a service account whose access is limited to that unit. In OpenLDAP terms:

   ```ldif
   olcAccess: to attrs=userPassword by dn.exact="cn=ligo-idp,ou=services,dc=prod,dc=internal" write by self write by anonymous auth by * none
   olcAccess: to dn.subtree="ou=ligo-accounts,dc=prod,dc=internal" by dn.exact="cn=ligo-idp,ou=services,dc=prod,dc=internal" write by users read by * none
   ```

4. Set `olcPasswordHash` to the scheme you want. The plugin sets passwords with the Password Modify operation, so the directory hashes them, and it cannot check which scheme is used.

### Register the plugin

1. In SPIRE, register the plugin as `spiffe://<trust domain>/ligo/plugin/openldap`, with the selectors `unix:uid` of the user `ligo` and `unix:sha256` of the binary.
2. In Vault or OpenBao, store the service account's DN and password in a KV v2 secret, as `username` and `password`. Give the plugin a JWT role bound to its SPIFFE ID and audience, with a policy that can only read that secret.
3. Check the registration. Run as the user `ligo`, the binary prints the SPIFFE IDs that the agent issues to it, and exits:

   ```bash
   sudo -u ligo /usr/lib/ligo/plugins/ligo-plugin-openldap -svids /run/spire/prod/agent.sock
   ```

### Configure

Add the plugin to `server.yaml`, with the hash that `sha256sum /usr/lib/ligo/plugins/ligo-plugin-openldap` prints. `examples/server.yaml` has a full example.

```yaml
identity_providers:
  - type: "openldap.v1"
    builtin: false
    binary: "ligo-plugin-openldap"
    sha256: "<64-hex-sha256-of-ligo-plugin-openldap>"
    instances:
      - name: "ldap-prod"
        zone: prod
        svid_selector:
          match_expr: 'path == "/ligo/plugin/openldap"'
          jwt_audience: ["https://vault.prod.internal"]
        config:
          url: "ldaps://openldap.prod.internal:636"
          service_ou_dn: "ou=ligo-accounts,dc=prod,dc=internal"
          allowed_endpoints: ["openldap.prod.internal:636"]
          # ca_file: "/etc/ligo/tls/corp-ca.crt"
          bootstrap_credential:
            source: vault
            address: "https://vault.prod.internal:8200"
            auth_mount: "jwt-spiffe"
            role: "ligo-plugin-openldap-prod"
            jwt_audience: "https://vault.prod.internal"
            kv_path: "kv/data/ligo/bootstrap/ldap-prod"
```

`ca_file` holds the roots that verify both the directory and that Vault; without it, the system roots do. It is read once, when the instance is configured.

A platform uses the plugin by naming this instance as its `identity_provider`. Its provider must accept `EXTERNAL_DIR`, and the platform must verify each account against the directory as `uid=<principal>,<service_ou_dn>`.

### Upgrade

A package update changes the binary's hash, and two things pin it: `plugins[].sha256` in `server.yaml`, and the `unix:sha256` selector in SPIRE. Until both match, `ligo` refuses to start the new binary and the agent does not issue it an SVID. A running plugin keeps working, but it cannot be started again if it stops, so do the steps below together. A reload is not enough, because `SIGHUP` only reloads certificates.

1. Upgrade the package on one replica, and note the new hash with `sha256sum /usr/lib/ligo/plugins/ligo-plugin-openldap`.
2. Add a SPIRE entry with the new hash, keeping the old entry, and run the `-svids` check above.
3. Set the new hash in `server.yaml` and restart `ligo` on that replica.
4. Repeat steps 1 and 3 on the other replicas.
5. Delete the SPIRE entry with the old hash.

The release builds the plugin reproducibly, so you can compare the hash with your own build of the same tag.

### Known limits

- **Rotation window.** An OpenLDAP account has one password. Between Stage 1 changing it and Stage 3 storing it, the credential the workload has stored does not bind. The window lasts as long as those two stages.
- **Password policy.** A directory policy that refuses a generated password shows up as `DIRECTORY_REJECTED`, which is terminal.
- **Foreign entries.** An entry at the account's DN without the binding's `description` tag is never changed or deleted: the binding fails with `RESOURCE_OWNED_BY_OTHER_BINDING`, and cleanup skips it.
