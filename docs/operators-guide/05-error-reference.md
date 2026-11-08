# Error reference

## Admin API problems

The admin API answers errors as `application/problem+json`, with `type` `urn:ligo:problem:<slug>`. Each response has an `X-Request-Id`, which is also in the logs and the audit entries it caused.

::: landscape

| Slug | Status | Means | Do |
| :------------------------------- | :-- | :------------------------------ | :----------------------------- |
| `unauthenticated` | 401 | No valid SVID or credential | Check the socket, the SVID, or the LDAP user |
| `forbidden` | 403 | The role does not cover this jurisdiction, or an SVID tried what takes a person | Check `authorization.bindings` |
| `rate-limited` | 429 | Too many requests or logins | Wait for `Retry-After`; raise the limit if it is real traffic |
| `not-found` | 404 | Absent, or not visible to you: the two look the same on purpose | Check the name and your jurisdictions |
| `validation-failed` | 422 | The request is not acceptable | Its `detail` names the field |
| `immutable-field` | 422 | A field that cannot change after creation | File a new resource |
| `sample-not-matched` | 422 | A sample SPIFFE ID does not match the regex | Fix either |
| `jurisdiction-unresolvable` | 422 | The regex's fixed beginning identifies no single jurisdiction | Make its beginning fixed enough |
| `source-not-exact` | 422 | The Vault store releases to one exact SPIFFE ID, and this regex matches more | Register one source per workload |
| `account-not-registered` | 422 | The jurisdiction belongs to an account that is not registered, or is retired | Have an `account_admin` register it, or correct the jurisdiction |
| `account-exists` | 409 | The account exists, or once did: a retired name is never reused | Choose another name |
| `account-in-use` | 409 | The account still has sources or targets that are not retired | Retire them first; the `detail` counts them |
| `account-jurisdiction-mismatch` | 422 | The jurisdiction is an account's, but is not in the form of `source_jurisdiction` or `target_jurisdiction` | Use the form the `detail` names |
| `namespace-mismatch` | 422 | The target's definition holds another namespace than its jurisdiction gives | Use the value the `detail` names |
| `namespace-jurisdiction-mismatch` | 422 | A namespaced platform holds only tenancies, and this jurisdiction is not one | Choose a jurisdiction in the form of `target_jurisdiction`, or another platform |
| `widening-not-allowed` | 422 | A source can only narrow, and this would add workloads, or the check was undecided | Register a new source |
| `flow-destination-not-allowed` | 422 | A flow's destination is outside the platform's `allowed_endpoints` | Fix the flow, or ask the platform team |
| `interconnect-denied` | 403 | The interconnection policy denies this pair of jurisdictions | Ask whoever owns `governance.interconnects` |
| `four-eyes-violation` | 403 | The requester tried to decide their own request | Ask another approver |
| `distinct-approver-required` | 403 | You already decided another side | Ask another approver |
| `side-required` | 400 | You could decide several sides | Name one with `--side` |
| `payload-mismatch` | 409 | The request changed since you read it | Read it again |
| `revision-conflict` | 409 | Someone changed the resource since you read it | Read it again |
| `resource-changed` | 409 | A resource it relies on changed | File it again |
| `normalization-drift` | 409 | The source or target changed since validation | File it again |
| `governance-policy-changed` | 409 | The policy changed since it was filed | File it again |
| `change-request-pending` | 409 | The resource has a pending request | Decide or withdraw that one |
| `change-request-not-pending` | 409 | It has already been decided | Nothing |
| `dependency-pending` | 409 | It depends on a request not yet applied | Decide that one first |
| `binding-exists` | 409 | That source and target are already bound | Update the binding |
| `binding-busy` | 409 | A workflow is running on it | Wait, then repeat |
| `invalid-transition` | 409 | Not possible in its phase | Check the phase |
| `resource-in-use` | 409 | Bindings use it | Revoke them first |
| `resource-deprecated` | 409 | The source, target or level is not `ACTIVE` | Reactivate it, or use another |
| `break-glass-limit` | 429 | The policy's `max_open` is reached | Ratify or revert open ones |
| `break-glass-open` | 409 | The binding has an open emergency change | Ratify or revert it first |
| `break-glass-not-open` | 409 | Nothing is left to ratify or revert | Nothing |
| `executor-alive` | 409 | That replica still has database sessions | Confirm the host is down |
| `executor-self` | 409 | You asked a replica to recover itself | Ask another replica |
| `maintenance` | 503 | Maintenance mode is on | Wait, or `ligo maintenance off` |
| `unavailable` | 503 | A dependency cannot be reached | Check its logs and health |
| `internal` | 500 | An unexpected error | Look up `X-Request-Id` in the logs |

:::

## Plugin errors

A binding's `status.message` gives the code. A retryable error is retried within the step, then the binding is `FAILED`; after that, or for a terminal error, fix the cause and `ligo retry`. Messages are fixed: backends' texts can echo statements or data, and are never copied.

::: landscape

| Code | Plugin | Retried | Means | Do |
| :--------------------------------- | :--------- | :------ | :-------------------------- | :----------------------- |
| `INVALID_CONFIG` | all | no | An instance's `config` breaks a rule | Fix the field it names |
| `INVALID_SELECTOR` | all | no | `match_expr` is not valid | Fix the expression |
| `SVID_SELECTION_FAILED` | all | no | Not exactly one SVID matched | Check the SPIRE entries, with `-svids` |
| `WORKLOAD_API_UNAVAILABLE` | all | yes | The agent's socket does not answer | Check the agent |
| `SVID_UNAVAILABLE` | `vault.v1` | yes | The JWT-SVID cannot be fetched | Check the agent and the entry |
| `UNKNOWN_INSTANCE` | all | no | The instance is not configured | Check `server.yaml` |
| `INVALID_BINDING` | all | no | The binding's ID is not valid | Report it |
| `INVALID_PRINCIPAL` | `postgres.v1`, `openldap.v1` | no | The principal name is outside the grammar | Check `principal_prefix` |
| `INCOMPATIBLE_IDENTITY_MODE` | `postgres.v1`, `vault.v1` | no | The wiring gave the wrong mode | Check the platform's wiring |
| `RESOURCE_OWNED_BY_OTHER_BINDING` | `postgres.v1`, `openldap.v1` | no | A role or account of that name is another binding's, or untagged | Remove or rename it; never reuse names |
| `BOOTSTRAP_CREDENTIAL_UNAVAILABLE` | `postgres.v1`, `openldap.v1` | yes | The credential cannot be read from Vault | Check Vault, the role, the policy |
| `BOOTSTRAP_CREDENTIAL_REJECTED` | `postgres.v1`, `openldap.v1` | yes | The backend refused it, perhaps mid-rotation | Check the password in KV |
| `INVALID_SPEC` | `postgres.v1` | no | The requested spec is not valid | Report it |
| `PRIVILEGE_OUT_OF_BOUNDS` | `postgres.v1` | no | `grantable_roles` or `grantable_role_templates` was tightened | Change the access level, or the bound |
| `TARGET_UNAVAILABLE` | `postgres.v1` | yes | The database cannot be reached, or is going away | Check it |
| `TARGET_BUSY` | `postgres.v1` | yes | A concurrent change | It clears by itself |
| `ROLE_NOT_FOUND` | `postgres.v1` | no | A granted group role does not exist | Create it on the database |
| `TARGET_ACCESS_DENIED` | `postgres.v1` | no | The admin role lacks a right | Grant it: Setup Guide, *The plugins* |
| `ROLE_OWNS_OBJECTS` | `postgres.v1` | no | The role owns objects, so it cannot be dropped | Reassign them, then retry |
| `TARGET_REJECTED` | `postgres.v1` | no | Any other refusal | The SQLSTATE is in the logs |
| `DIRECTORY_UNAVAILABLE` | `openldap.v1` | yes | Network, TLS, LDAP `busy` or `unavailable` | Check the directory |
| `DIRECTORY_ACCESS_DENIED` | `openldap.v1` | no | LDAP result 50 | Check the service account's rights |
| `DIRECTORY_REJECTED` | `openldap.v1` | no | Any other refusal, such as a password policy | The result code is in the logs |
| `VAULT_UNAVAILABLE` | `vault.v1` | yes | Network, `429`, `5xx`; a sealed server is `503` | Check and unseal it |
| `VAULT_ACCESS_DENIED` | `vault.v1` | no | `403` | Check the plugin's policy |
| `VAULT_REJECTED` | `vault.v1` | no | Any other refusal | The status is in the logs |
| `SOURCE_NOT_EXACT` | `vault.v1` | no | The source's regex matches more than one ID | Register one source per workload |
| `DB_CONNECTION_NOT_CONFIGURED` | `vault.v1` | no | `vault-dynamic` needs `db_connection` | Set it |
| `UNKNOWN_STRATEGY` | `vault.v1` | no | Not `vault-static` or `vault-dynamic` | Check the platform's wiring |
| `PASSWORD_GENERATION_FAILED` | `openldap.v1` | yes | The host's random source failed | Check the host |

:::

## Engine errors in a binding's message

| Code | Means | Do |
| :--------------------------- | :----------------------------- | :-------------------------- |
| `SEALED_SECRET_UNAVAILABLE` | Transit cannot seal or unseal this attempt's secret | Bring Vault back, then retry: a new attempt rotates |
| `OUTPUT_VALIDATION_FAILED` | A plugin's output broke its schema, or pointed outside `allowed_endpoints` | Audited: treat a surprise as a compromised plugin |
