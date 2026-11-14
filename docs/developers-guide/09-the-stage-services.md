# The stage services

A plugin of each kind implements one more service. All three follow the same rules, in §5.8 of the specification; this chapter states them once and then goes through the kinds.

## The rules every plugin follows

1. **Idempotent.** `Ensure*` converges: it creates what is missing, changes what differs and removes what the binding no longer asks for. Calling it again changes nothing. `Cleanup*` succeeds when the resource is already gone. `ligo` retries, and a workflow can run again after a crash.
2. **Named by `ligo`.** Name every resource from `BindingContext.derived_principal_name`, with no prefix of your own. Where the backend allows a note on the object (an LDAP `description`, a PostgreSQL `COMMENT ON ROLE`, a Vault role's metadata), write `ligo:binding_id=<uuid>`.
3. **Owned.** When `Ensure*` finds an object tagged with another binding, fail with `RESOURCE_OWNED_BY_OTHER_BINDING`. When `Cleanup*` finds one, leave it and answer `skipped_not_owner = true`. Never touch what you did not make.
4. **No injection.** A value from a request goes into SQL, DDL, an LDAP filter or DN, or a Vault template only if it matches a strict identifier grammar that you check yourself, with no quoting tricks. The values that come from `ligo` are already safe, but your plugin is the last line.
5. **Within bounds.** An access level can grant only what the platform's configuration allows (for a database, the `grantable_roles`). Check it in `ValidateTarget`, again in `ValidateBinding`, and again in `EnsureTarget`.
6. **Secrets stay secret.** A generated password uses `[A-Za-z0-9]`, at least 32 characters, from `crypto/rand` (`pluginsdk.GeneratePassword`). A secret is returned only in the response that makes it, and left out when `secret_unchanged` is true: when the principal exists and `rotate_static_secrets` is false, do not change its credential. Never put a secret in a log, an error or the output. `pluginsdk.Secret` prints as `[redacted]` in `%v`, JSON and `slog`, and `pluginsdk.NewRedactingHandler` wraps a `slog` handler to the same end.
7. **Register-only targets.** `ValidateTarget` and `ValidateBinding` read from the platform; they never change it.

## Identity providers

```go
type IdentityProviderPluginServer interface {
    EnsureIdentity(context.Context, *pluginv1.EnsureIdentityRequest) (*pluginv1.EnsureIdentityResponse, error)
    CleanupIdentity(context.Context, *pluginv1.CleanupIdentityRequest) (*pluginv1.CleanupIdentityResponse, error)
}
```

`Describe` sets `Capabilities` to `IdentityProviderCapabilities{ProducedIdentityMode: ...}`: exactly one mode, never unspecified.

`EnsureIdentity` returns an `IdentityArtifact`:

- `mode` and `principal_id`, which is `derived_principal_name` (case-transformed if the backend needs it);
- the backend's own form, such as an LDAP DN, in `distinguished_name`, and group names in `groups`;
- `static_secret`, only when the mode has a password and it was just made. `ligo` seals it and removes it from the artifact before the next stage.

The shipped `openldap.v1` creates one account per binding in one organizational unit, from a password it generates. Read `cmd/plugins/ligo-plugin-openldap`.

## Platform providers

```go
type PlatformProviderPluginServer interface {
    GetUISchemas(context.Context, *pluginv1.GetUISchemasRequest) (*pluginv1.GetUISchemasResponse, error)
    ValidateTarget(context.Context, *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error)
    ValidateBinding(context.Context, *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error)
    EnsureTarget(context.Context, *pluginv1.EnsureTargetRequest) (*pluginv1.EnsureTargetResponse, error)
    CleanupTarget(context.Context, *pluginv1.CleanupTargetRequest) (*pluginv1.CleanupTargetResponse, error)
}
```

A target is a resource the platform team publishes, with **access levels**: named sets of privileges. A binding picks one level.

- `ValidateTarget` checks a target's `definition_json` and its levels, and returns the normalized definition and, for each level, `privileges`: a sorted list without duplicates. If level A's privileges are a subset of B's, then B must be at least as powerful as A; `ligo` relies on it.
- `ValidateBinding` composes the **requested spec** of a binding from the target, the level and the binding's parameters, and rejects a parameter that would grant more than the level. The `privileges` it returns must equal the level's.
- `EnsureTarget` makes the binding real on the platform and returns `finalized_client_spec_json`, which the workload will receive as `spec`; a `secret_payload` for the secret store; and the endpoints it declared.
- `CleanupTarget` removes everything the binding owns, found by the binding's ID or its derived name, whatever its revision.

The `secret_payload` depends on the identity mode:

| Mode | The payload is |
| :--------------------------------- | :-------------------------------------------------- |
| `TARGET_LOCAL` | A `StaticSecret` for the user you made on the target. |
| `EXTERNAL_DIR` | The identity provider's secret, which `ligo` passes on; the target only checks it against the directory. |
| `DELEGATED_DYNAMIC` | A `DelegatedRoleSpec`: the statements the secret store runs to create and drop a user, with a lease. |

For a `DelegatedRoleSpec`, use only the store's template variables, `{{name}}`, `{{password}}` and `{{expiration}}`, and identifiers you checked. Set `default_ttl_seconds` and `max_ttl_seconds` from the instance's configuration if it has them, and leave **0** when it has none: `ligo` then fills the value from `server.yaml`, so every platform plugin gets the platform team's default for free. `pluginsdk.CredentialTTL` checks a pair against the limits (a minute to 720 hours). The shipped `postgres.v1` does exactly this with `credential_ttl` and `credential_max_ttl`.

If your platform has namespaces, say in `PlatformProviderCapabilities.namespace_field` which top-level field of a target's definition holds one, so that `ligo` can check it against the platform's `namespaceTemplate`.

## Secret stores

```go
type SecretStorePluginServer interface {
    EnsureSecretStore(context.Context, *pluginv1.EnsureSecretStoreRequest) (*pluginv1.EnsureSecretStoreResponse, error)
    CleanupSecretStore(context.Context, *pluginv1.CleanupSecretStoreRequest) (*pluginv1.CleanupSecretStoreResponse, error)
}
```

`Describe` lists the **secret storage strategies** the store supports, each with the identity modes it works with, and `SubjectMatch`. `SUBJECT_MATCH_EXACT` says the store releases a credential only to one exact SPIFFE ID; `ligo` then refuses a binding whose source it could only approximate by a pattern. A store that cannot be exact must say so, and gets only bindings whose source is a single identity.

`EnsureSecretStore` gets the payload of stage 2 with the secret unsealed in memory, and does what the strategy says. `vault.v1` stores a static secret in a KV engine, or creates a database role for a delegated one, and in both makes the policy and the JWT role that let exactly the binding's workload read the credential. It returns `finalized_client_auth_json`, which the workload will receive as `auth.config`: where to log in and what to read. For the Go SDK to work with a new store type, the output must say how a workload authenticates, as `vault.v1` does with `address`, `audience`, `authMount`, `role` and the path.

`CleanupSecretStore` removes what the store made. `vault.v1` also revokes the leases of credentials issued, so access ends when the binding does.

## The bootstrap credential

A plugin often needs a credential for its backend: the admin of the database, the directory's service account. It is never in the instance's configuration. The configuration says where to read it:

```json
"bootstrap_credential": {
  "source": "vault", "address": "https://vault.example.com:8200",
  "auth_mount": "jwt-spiffe", "role": "ligo-plugin-postgres",
  "jwt_audience": "https://vault.example.com", "kv_path": "kv/data/ligo/bootstrap/postgres"
}
```

`pluginsdk.BootstrapCredentialConfig` is that object, with `Validate` for its shape, and `pluginsdk.NewBootstrapCredential` reads it with the instance's JWT-SVID, so it exists only in the plugin's memory. The audience must be one the instance's `svidSelector.jwtAudience` lists. Connect to the backend with it for the length of one call and let it go.
