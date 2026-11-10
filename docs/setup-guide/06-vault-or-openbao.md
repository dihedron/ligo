# Vault or OpenBao

The same configuration works on both. `ligo` and its plugins log in with their JWT-SVIDs, so enable JWT authentication trusting your SPIRE OIDC discovery provider:

```bash
vault auth enable -path=jwt-spiffe jwt
vault write auth/jwt-spiffe/config oidc_discovery_url=https://oidc.prod.internal
vault secrets enable transit
vault secrets enable -version=2 kv
```

## Sealing

Secrets pass between pipeline stages through durable checkpoints, sealed with Transit first. The key can only be used by `ligo`, and is not exportable.

A second key, of type `ed25519`, signs checkpoints of the audit chain, so that a chain rewritten in the database no longer verifies. `ligo` signs with it and reads its public keys, to verify signatures without calling Vault each time:

```bash
vault write -f transit/keys/ligo-interstage
vault write transit/keys/ligo-audit type=ed25519
vault policy write ligo-sealer - <<'HCL'
path "transit/encrypt/ligo-interstage" { capabilities = ["update"] }
path "transit/decrypt/ligo-interstage" { capabilities = ["update"] }
path "transit/sign/ligo-audit"         { capabilities = ["update"] }
path "transit/keys/ligo-audit"         { capabilities = ["read"] }
HCL
vault write auth/jwt-spiffe/role/ligo-sealer role_type=jwt user_claim=sub \
  bound_subject=spiffe://prod.internal/ns/sys/sa/ligo \
  bound_audiences=https://vault.prod.internal token_policies=ligo-sealer token_ttl=15m
```

A sealed or unreachable server, or a missing key, stops `ligo` at startup, with nothing written. The unit restarts it with a back-off, from 5 s to 5 min.

## The plugins' bootstrap credentials

A plugin that needs a password for its backend reads it from a KV v2 secret, with its JWT-SVID. Give each plugin a role that can read only its own:

```bash
vault kv put -mount=kv ligo/bootstrap/postgres username=ligo_target_admin password=...
vault policy write ligo-plugin-postgres - <<'HCL'
path "kv/data/ligo/bootstrap/postgres" { capabilities = ["read"] }
HCL
vault write auth/jwt-spiffe/role/ligo-plugin-postgres role_type=jwt user_claim=sub \
  bound_subject=spiffe://prod.internal/ligo/plugin/postgres \
  bound_audiences=https://vault.prod.internal token_policies=ligo-plugin-postgres token_ttl=15m
```

`ligo-plugin-openldap` needs the same, with the service account's DN as `username`.

## The secret store

`ligo-plugin-vault` needs no bootstrap credential. Its role may create only per-binding objects, and `allowed_parameters` stops a compromised plugin giving a workload any other policy:

```hcl
path "kv/data/bindings/*"     { capabilities = ["create", "update", "read"] }
path "kv/metadata/bindings/*" { capabilities = ["create", "update", "read", "delete"] }
path "sys/policies/acl/binding-*" { capabilities = ["create", "update", "read", "delete"] }
path "auth/jwt-spiffe/role/binding-*" {
  capabilities = ["create", "update", "read", "delete"]
  allowed_parameters = {
    "token_policies" = ["binding-*"]
    "*" = []
  }
}
```

With `vault-dynamic`, also allow these, and configure a connection of the database secrets engine to the target, with `allowed_roles="binding-*"`:

```hcl
path "database/roles/binding-*" { capabilities = ["create", "update", "read", "delete"] }
path "sys/leases/revoke-prefix/database/creds/binding-*" { capabilities = ["update", "sudo"] }
```

Workloads then log in with their own JWT-SVIDs, to the per-binding role the plugin keeps. Their tokens read one path only.
