# The pipeline

Identity origins, target systems and secret stores vary independently. A plugin per combination would multiply, so provisioning has three orthogonal stages, each a checkpointed step.

| Stage | Interface | Decides | Shipped |
| :---- | :--------------- | :----------------------------- | :----------------------- |
| 1 | `IdentityProvider` | Who the principal is | `svid.v1`, `target-local.v1`, `delegated-dynamic.v1`, `openldap.v1` |
| 2 | `PlatformProvider` | What it may do. The only stage that connects to the platform | `postgres.v1` |
| 3 | `SecretStore` | Where the credential lives, and who may read it | `none.v1`, `vault.v1` |

## Identity modes

| Mode | Stage 2 output | Stores | Source of the secret |
| :---------------- | :-------------- | :----------- | :---------------------- |
| `SVID` | None | `none.v1` | None: the workload uses its SVID |
| `EXTERNAL_DIR` | None | `vault.v1` | Stage 1's, forwarded by the engine |
| `TARGET_LOCAL` | A static secret | `vault.v1` | Stage 2's |
| `DELEGATED_DYNAMIC` | Statements | `vault.v1` | Vault generates credentials |

At startup, `ligo` refuses wiring that the plugins' declarations do not support. `postgres.v1` does not accept `SVID`: see *Design decisions*.

## Applying

![Applying a binding.](apply-sequence.pdf){width=100%}

`Ensure*` converges: it creates what is missing, updates what differs and revokes what the revision no longer requests. So a retried or repeated step is safe, and the reconciler can use the same path to repair drift.

Only after every stage succeeds does the transaction promote the **active snapshot** that workloads are served. A failed attempt leaves the last good snapshot in place.

## Deleting

Deletion runs in reverse, Stage 3 to 1, driven by recorded state, not by the plan. Visibility is removed in the transaction that starts it, so the API is right immediately. Cleanup succeeds on what is absent and skips what it does not own, reporting `skipped_not_owner`, which is audited.

`postgres.v1` also ends the role's sessions, so access ends with the revocation.

## Reconciling and propagating

The reconciler reapplies bindings on a schedule, with jitter and a concurrency bound, and rotates static secrets when due. The propagator re-applies bindings when their source or target changed, removals of access first, so a containment does not wait behind routine work.

## Plugin rules

Every plugin must follow these:

- **Idempotent and convergent.**
- **Ownership**: names from the binding, tagged, foreign resources refused.
- **No injection**: identifiers pass a strict grammar and are quoted; privileges stay within bounds, checked at publication, at validation and again at apply, so a tightened bound applies even to earlier levels.
- **Secrets** only in the response meant for them, and never changed unless rotating.
- **Parameters never add privilege.**
- **Targets are registered, not created.**

## How `postgres.v1` keeps secrets out of logs

It computes the SCRAM-SHA-256 verifier itself and sends that, so a statement log holds no password. PostgreSQL's error text can echo a statement, so only the SQLSTATE is logged. It applies a binding in one transaction, so a crash cannot leave a role without its tag, which would look foreign for ever.

## How `vault.v1` confines a credential

Per binding, it keeps the secret or database role, a policy reading only that path, and a JWT role that gives that policy only to one exact SPIFFE ID. Its own policy can only create `binding-*` objects, with `allowed_parameters` limiting the policies its roles can carry. Each call revokes its token at the end.
