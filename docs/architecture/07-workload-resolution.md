# Workload resolution

A workload asks: what may I use, and how? It must be fast, available, and never wrong in the dangerous direction.

## The path

1. **Authenticate.** An X.509-SVID over mTLS, preferred as it has no bearer token, or a JWT-SVID with an exact audience, `iat` required and a bounded lifetime. The certificate is verified against the bundle of its own trust domain.
2. **Resolve** from an in-memory cache of `v_active_bindings`, read by `ligo_reader`, which can read only that view. `LISTEN ligo_bindings_changed` reloads it at once, and a full reload bounds the staleness if a notification is lost.
3. **Match** the caller's SPIFFE ID in full, with RE2, against both the binding's active regex and its source's **current** regex.
4. **Answer** with each binding's `spec` and `auth`, and an `ETag`.

## Why both regexes

A narrowed source must take effect at once, without waiting for each binding to be re-applied, so the current regex also applies. The active regex still applies, so a binding is never served to more than what was provisioned. A binding is also served only before its expiry.

The resolver validates each regex again, in case someone wrote to the database directly.

## Failure

It fails closed. A bundle error, or a cache older than `max_staleness`, gives `503`, not stale or unverified answers. Workloads keep working with the credentials they hold.

## Who may read a credential

`ligo` tells a workload where its credential is. The store releases it. For `vault.v1`, that decision is Vault's JWT role, with `bound_subject` the workload's exact SPIFFE ID. The two must agree, which is why `ligo` refuses a source the store cannot express exactly: see *Design decisions*.
