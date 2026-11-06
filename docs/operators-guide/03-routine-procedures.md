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

Read the binding's message, fix the cause (*Error reference*), then `ligo retry <binding>`. It is a new attempt, which rotates static secrets.

## Revoking

```bash
ligo delete binding <name> -r <revision>                 # one binding
ligo target revoke-bindings <target> --source-scope 'cloud/*' --comment "..."   # containment
```

One owner is enough to revoke: the source's, the target's or the platform's. No other can veto it. The API stops serving it at once; the workflow then removes the store's objects, the role and any account, in that order.

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
