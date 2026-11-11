# Routine procedures

## Reviewing change requests

```bash
ligo cr review                     # the queue awaiting you, interactive
ligo cr list --awaiting-me
ligo cr get <id>                   # its diff and payloadSha256
ligo cr approve <id> --sha256 <payloadSha256> --side TARGET --comment "..."
ligo cr decline <id> --side TARGET --comment "..."
```

An approval names the payload's hash, so you approve exactly what you read. A requester can never decide their own request, and with distinct approvers on, nobody decides two sides. If a request says `binding-busy`, the binding is provisioning: it stays `PENDING`, so approve again later.

## Rotating a credential

```bash
ligo rotate <binding>
```

The reconciler also rotates each platform's static secrets at its `rotation_interval`. Between the target changing a password and the store holding the new one, the stored credential does not connect, so workloads must retry a failed connection by reading the credential again.

## Retrying a failure

Read the binding's message. A retryable cause needs nothing from you: `ligo` retries the binding by itself once the cause is gone (`ligo audit list` shows `system:auto-retry`). For a final cause, fix it (*Error reference*), then `ligo retry <binding>`. Either way a retry is a new attempt, which rotates static secrets.

## Revoking

```bash
ligo delete binding <name> -r <revision>                 # one binding
ligo target revoke-bindings <target> --source-jurisdiction 'cloud/*' --comment "..."   # containment
```

One owner is enough to revoke: the source's, the target's or the platform's. No other can veto it. The API stops serving it at once; the workflow then removes the store's objects, the role and any account, in that order.

## Managing accounts

Use the **Accounts** page of the web UI, or the CLI, as an `account_admin`:

```bash
ligo account register acme --display-name "Acme Corp"
ligo account list
ligo account get acme      # with its counts of sources, targets and bindings
ligo account retire acme   # asks you to type the name
```

To add a tenant:

1. Register the account. It applies at once, and is audited.
2. In the directory, create its unit and groups under the configured `search_base`. Roles follow within moments, on every replica, and existing sessions pick them up at their next check.
3. For each tenancy on a shared platform, have the platform team create the schema and its roles.
4. In SPIRE, register the account's workloads under its path.

An unregistered account gets no roles, even if its groups exist, and its sources and targets are refused with `422 account-not-registered`.

To retire one, first retire its sources and targets; otherwise `409 account-in-use`. **Retiring cannot be undone, and the name can never be registered again**, because audit entries and SPIFFE paths refer to it. Its groups stop granting roles at once.

### Who decides for an account

Inside one account, two of its approvers decide: one for the `SOURCE` side, another for `TARGET`, when `require_distinct_approvers_across_jurisdictions` is on. An account with one approver cannot approve its own bindings. Across accounts, each account decides its side.

An approver of the platform's jurisdiction may also decide a binding's `TARGET` side, for a tenant nobody can reach. Use it sparingly: the target's account no longer consents, although it is told and can revoke alone. It never replaces the source's consent. The audit entry carries `decidedAs: PLATFORM`.

## Rolling restart, and maintenance

Any change to `server.yaml` other than certificate files needs a rolling restart. `systemctl reload ligo` reloads certificate files only. `ligo` drains active requests for up to 15 s on `SIGTERM`.

Maintenance mode is one setting for the whole cluster:

```bash
ligo maintenance on -m "why"       # needs admin.full_access
ligo maintenance status --wait-drained
ligo maintenance off
```

While it is on, new change requests, approvals, retries, rotations and break-glass are refused with `503 maintenance`. In-flight workflows finish; the sweeper still removes access; reads and the workload API keep serving; the UI shows a banner.

## Upgrading

Follow *Upgrades and removal* in the Setup Guide: drain, migrate, roll out, resume.

## Backing up

The schemas `public` and `dbos` live in one database and must be backed up together, with point-in-time recovery. Restoring is in *Incident procedures*. Keep the Vault Transit key too: without it, sealed checkpoints cannot be opened, and those attempts fail until retried.

## Rotating `ligo`'s own secrets

| Secret | How |
| :------------------- | :------------------------------------ |
| Bootstrap credential of a plugin | Change it on the backend and in KV. The plugin reads it again when due; a refused credential is retried |
| Database roles' passwords | Change them, update `ligo.env`, rolling restart |
| LDAP bind password, webhook secrets | Update `ligo.env`, rolling restart |
| TLS certificates from files | Replace the files, `systemctl reload ligo`. A file that fails to load keeps the old one, and logs `ERROR` |
| SVIDs | SPIRE rotates them; nothing to do |
| Transit key | Rotate it in Vault: versions keep older ciphertext readable |
