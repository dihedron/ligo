# Instances managed at run time: guides

- **Spec:** `.specs/ligo-instances.md`
- **Status:** draft. Exact output is filled in when chunks 4 and 5 are implemented. The commands follow the spec.

These guides are run by hand, one step at a time, against the lab. Two LDAP users are needed: one files the requests and the other approves them, because the requester can never decide. Here they are `alice` (operator) and `bob` (approver), both on jurisdiction `dc/platform`; chunk 7 adds them to the lab directory.

## G-1. Add a secret store instance, then a platform, with no restart

1. **As `alice`, write `store.yaml`:**

   ```yaml
   kind: SecretStore
   metadata: {name: vault-test, jurisdiction: dc/platform, realm: corp}
   type: vault
   svidSelector:
     matchExpr: 'path == "/ligo/plugin/vault" && hint == "vault-test"'
     jwtAudience: ["https://vault.prod.internal"]
   config:
     address: https://vault.prod.internal:8200
     ca_pem: |
       -----BEGIN CERTIFICATE-----
       …
       -----END CERTIFICATE-----
     bootstrap_credential: {jwt_audience: https://vault.prod.internal, kv_path: …}
   ```

   The SPIRE entry for `hint == "vault-test"` must exist first (spec §14). Without it, step 2 fails with `SVID_SELECTION_FAILED`.
2. **File it:** `ligo apply -f store.yaml`. Expect one change request, `PENDING`, with one `OWNER` side on `dc/platform`.
3. **`alice` tries to approve:** `ligo change-request approve <id>`. Expect `403 four-eyes-violation`.
4. **As `bob`:** `ligo change-request get <id>` shows the definition and its `payloadSha256`. Then `ligo change-request approve <id>`. Expect `APPLIED`.
5. **Check it on every replica:** `ligo list secret-stores` shows `vault-test` ACTIVE. On both replicas, the log shows `plugin instance resolved … instance=vault-test`. No replica restarted (`systemctl status ligo`: same start time).
6. **A platform wired to it:** as `alice`, write a `kind: Platform` manifest with `secretStore: {type: vault, instance: vault-test}`. Then `ligo apply`, and `bob` approves. `ligo platform list` shows it with health `serving`.

## G-2. Bulk creation with `ligo apply`

1. **Write one file** with a new identity provider instance, a secret store instance, and a platform wired to both.
2. **`ligo apply -f all.yaml`.** The two instances are filed. The platform is reported as waiting for its wiring instances, which are not ACTIVE yet.
3. **`bob` approves the two requests.**
4. **`ligo apply -f all.yaml` again.** The two instances exist and are unchanged, so nothing is filed for them; the platform is filed. `bob` approves it.

## G-3. Refusals

1. **An endpoint outside `instance_bounds`:** set `address: https://evil.example:8200` and apply. Expect `422 validation-failed`, naming the endpoint and the type's bounds.
2. **A file path:** `ca_file: /etc/shadow`. Expect `422`: the key is unknown to the schema.
3. **A shared SVID across jurisdictions:** a second store instance in `dc/other` with the same `matchExpr`. Expect `422`.
4. **Retiring an instance in use:** `ligo delete secret-store vault-test` while the platform of G-1 uses it. Expect `409 instance-in-use`.
5. **An old `server.yaml`:** start ligo with a `platforms:` section. Startup refuses it, and the error names `.specs/ligo-instances.md`.

## G-4. Drift

1. **On the database, as a superuser, edit a row directly:**
   `UPDATE instances SET definition = jsonb_set(definition, '{config,address}', '"https://vault.prod.internal:8201"') WHERE name = 'vault-test';`
2. **Within `reconciliation.interval`,** check three things:
   - the log has an `ERROR` naming the instance;
   - `ligo_instance_drift{kind="SECRET_STORE",name="vault-test"} 1`;
   - `ligo audit list` shows `SYSTEM_INSTANCE_DRIFT`.

   `ligo list secret-stores` no longer offers it.
3. **Fix it:** `alice` files the intended definition with `expectedRevision`, and `bob` approves. The metric returns to 0, and the instance is offered again.

## G-5. Web UI

1. **As `alice`:** go to Platforms, then New. Pick type `postgres`, fill the metadata, paste the config as YAML, and submit. Expect the change request page.
2. **A config key the schema does not know** shows an error on submit, and nothing is filed.
3. **As `bob`:** the request is in the review queue, with its diff. Approve it, and the platform appears in the list.
