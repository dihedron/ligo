# Operating ligo

This guide is for the people who install and run `ligo`. It grows towards the first release; for now it covers the one external plugin. The rules behind each step are in [the plugin's specification](../.specs/ligo-openldap-plugin.md).

## The `openldap.v1` identity provider

`ligo-plugin-openldap` creates one account per binding in an organizational unit of an OpenLDAP directory, and gives it a generated password. The password reaches the workload through the secret store, and a platform that authenticates its users against the same directory accepts it.

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
