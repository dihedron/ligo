# Audit and outbox pruning

- **Version:** 1.3 (2026-11-11), approved; 1.1: the 24-hour floor in `audit_prune`, and the T-13 residual risk stated (accepted: the SIEM copy is the authoritative record); 1.2: the export file as built, `SYSTEM_AUDIT_*` action names; 1.3: `Append` after a prune of every entry
- **Backlog:** items 1 (audit pruning) and 13 (outbox retention)
- **Branch:** `feature/pruning`
- **Main spec:** becomes 4.0.8; the sections it changes are listed at the end

## 1. Why

- `audit_log` only grows. Backups, restores and the full `audit verify` pass grow with it.
- `notification_outbox` keeps every delivered webhook event for 30 days. The 2-hour soak baseline grew it from 797 to 3,786 rows.

## 2. Decisions (the user, 2026-11-11)

| Question | Decision |
|---|---|
| Default audit retention | Off. `storage.audit.retention` unset keeps every entry. |
| Archive before delete | The operator exports. Pruning never deletes an entry no export has covered. |
| Who prunes the audit | A singleton loop in `serve`, under an advisory lock. |
| Outbox | Delivered rows kept a short, configurable window; abandoned rows kept longer. |

## 3. Audit pruning

### 3.1 Settings

```yaml
storage:
  audit:
    retention: 400d   # unset or 0: never prune (default)
```

- The value must be at least 24h. A shorter one fails the configuration check, so a typo cannot empty the table.

### 3.2 Export

`ligo audit export [--through ID] --out FILE` writes one JSON Lines file, in this order:

1. A header line: `{"kind":"header","from":N,"through":M,"exportedAt":"...","prevHash":"...","publicKeys":{"<key ID>":{"<version>":"<base64>"}}}`. `prevHash` is the `prev_hash` of entry N. The public keys are every version of the signing key, read from Vault at export time.
2. The signed checkpoints with `auditId` in N..M, and the newest one below N if any: after a prune, that one is the anchor, and its `entryHash` must equal the header's `prevHash`. Each: `{"kind":"checkpoint","auditId","entryHash","createdAt","keyId","signature"}`.
3. Every entry from N to M, in order: `{"kind":"entry","id","prevHash","entryHash","row":{...}}`, where `row` is the canonical (JCS) form that was hashed, so the hash is recomputed from the file alone.

Checkpoints come first so that the verifier knows them before it streams the entries.

- `--through` must name a checkpoint whose entry is still in the log. Without it, the export goes to the newest checkpoint. N is the oldest entry still in the database. Entries up to a checkpoint never change, so the export needs no snapshot.
- `--out` must not exist. On a refusal the file is removed.
- After writing, the CLI verifies the file with the keys it carries (§3.3). Only if that passes does it call `POST /v1/admin/audit/exports` with `{"through":M,"sha256":"<hex of the file>"}`. A file that does not verify is kept and not recorded.
- The server checks that M is a checkpoint (422 otherwise), and that no export through M or later is recorded (409 `audit-export-recorded`). It inserts a row in `audit_exports` and appends `SYSTEM_AUDIT_EXPORTED`, with M and the hash, in one transaction.
- `GET /v1/admin/audit/export?through=M` streams `application/x-ndjson`. It is read-only, in batches of 5000 entries, each its own statement. Errors before the first line are problems (422 not a checkpoint, 503 signer unavailable); an error later cuts the stream, and the CLI's verification fails on the file.
- Role: full access (`Grants.FullAccess`), for both the download and the record. `audit verify` needs only a viewer, but an export spans every jurisdiction, and recording one allows deletion.

### 3.3 Offline verification

`ligo audit verify --file FILE [--public-key KEYID/VERSION=BASE64 ...]` checks a file without the server:

- every checkpoint's signature verifies (`vault:vN:` and `local:v1:` signatures);
- the anchor below the first entry, if present, matches the header's `prevHash`;
- every entry re-hashes from the header's `prevHash`, ids increasing, starting at the header's `from`;
- every checkpoint's `entryHash` equals its entry's hash;
- the last entry is the header's `through`, and a checkpoint.

The public keys come from the header unless `--public-key` gives them; the output's `keysFromFile` says which. An auditor should take the keys from Vault (`GET transit/keys/ligo-audit`), not from the file under test. A file that does not verify prints its result, with `firstBroken` and `reason`, and exits non-zero.

### 3.4 What a prune deletes

On each pass of the loop (§3.5), the boundary B is the largest `audit_id` that is all of:

1. a signed checkpoint whose signature verifies;
2. at or below the newest recorded export;
3. one whose entry is older than `now - retention`.

Entries with `id <= B` are deleted. B's checkpoint stays, and it is the anchor that `Verify` already accepts for a pruned head: the oldest entry left has `prev_hash` equal to B's `entry_hash`.

Checkpoints are never deleted: one row per hour at most, which is small.

### 3.5 The loop

- It runs in the audit verify loop, after a valid incremental pass, on the replica holding `ligo_audit_verify`. It runs at most once every 24 h (a constant).
- It skips with a warning when the signer is unavailable, when the last verify was not valid, or when nothing is due.
- It calls `audit_prune(B)` (§3.6), then appends `SYSTEM_AUDIT_PRUNED` with B, the number of entries deleted, and the export it relied on.
- Metrics: `ligo_audit_pruned_entries_total`, and `ligo_audit_oldest_entry_timestamp_seconds`.

### 3.6 Deleting without opening T-13

- `ligo_app` keeps only `SELECT, INSERT` on `audit_log`. The append-only trigger stays.
- A new function, `audit_prune(through BIGINT) RETURNS BIGINT`, is `SECURITY DEFINER` and owned by the migrator role. `ligo_app` gets `EXECUTE` on it, and nothing else changes. The function:
  1. takes the chain's lock (the one `Append` takes), so no append interleaves;
  2. refuses unless `through` is a row of `audit_checkpoints`, `through <= max(audit_exports.through)`, and that checkpoint was signed more than 24 hours ago (the floor of `retention`, enforced in the database);
  3. sets `ligo.audit_prune = 'on'` for the transaction only (`set_config(..., true)`);
  4. deletes `audit_log` rows with `id <= through`, and returns the count.
- After a prune through the newest entry, the log is empty: the next `Append` chains onto the newest checkpoint's `entry_hash` (the anchor), not onto genesis.
- The trigger function lets a `DELETE` through only when `ligo.audit_prune` is `on`. Setting the variable alone gives nothing: `ligo_app` has no `DELETE` grant.
- What a compromised `ligo_app` can still do: it can insert an `audit_exports` row itself, so it can prune up to any checkpoint signed more than 24 hours ago, ignoring retention and without a real export. It cannot delete the last 24 hours, rewrite what remains, or delete checkpoints, and the gap shows: the oldest entry moves, `ligo_audit_oldest_entry_timestamp_seconds` jumps, and no `SYSTEM_AUDIT_PRUNED` entry explains it unless the attacker writes one. Before this change it could delete nothing. The SIEM's forwarded copy is the independent record. The threat model (T-13) says so.

### 3.7 Schema (migration 001, edited in place)

```sql
CREATE TABLE audit_exports (
    id          BIGSERIAL PRIMARY KEY,
    through     BIGINT NOT NULL UNIQUE,
    sha256      CHAR(64) NOT NULL,
    actor       VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- append-only trigger; ligo_app: SELECT, INSERT
```

`SYSTEM_AUDIT_EXPORTED` and `SYSTEM_AUDIT_PRUNED` are new actions (§4.3 action list). They are `SYSTEM_*` because they name no resource (`chk_audit_resource`).

## 4. Outbox retention

```yaml
notifications:
  delivered_retention: 24h   # default
  abandoned_retention: 720h  # default (30 days)
```

- The dispatcher's purge becomes two conditions in one `DELETE`: delivered rows after `delivered_retention`, abandoned rows after `abandoned_retention`.
- `0` for `delivered_retention` deletes a delivered row in the same pass that delivered it. That is allowed; the docs warn that SK-9 and `lab.sh serve test-webhook` then have nothing to compare.
- Negative values fail the configuration check.
- The soak and the webhook e2e run with the defaults: 24 h covers a 9-hour night.

## 5. Tests first

- **Unit:**
  - the boundary B rule (§3.4) on table-driven checkpoint, export and age sets;
  - export file writing and offline verification, including a tampered entry, a forged checkpoint, a missing last checkpoint, and keys from `--public-key`;
  - the configuration checks.
- **Integration, docker PostgreSQL:**
  - prune then `Verify` incremental and full, both valid;
  - a `DELETE` as `ligo_app` still refused, with and without `ligo.audit_prune` set;
  - `audit_prune` refused past the export, and refused at a non-checkpoint;
  - appends running during a prune keep the chain valid;
  - export, prune, then offline verification of the file;
  - outbox: delivered and abandoned rows purged on their own windows.
- **Lab:**
  - a release-run step: set retention to 24h on a lab with backdated entries, export, prune, verify full;
  - in the soak: a prune under load, with SK-8 still passing.

## 6. Chunks

1. **Outbox retention** (settings, dispatcher, config checks, tests).
2. **Schema and `audit_prune`** (001, integration tests on the function and the trigger).
3. **Export and offline verification** (API, CLI, `audit_exports`, `SYSTEM_AUDIT_EXPORTED`).
4. **The prune loop** (boundary rule, `SYSTEM_AUDIT_PRUNED`, metrics).
5. **Docs and main spec 4.0.8**:
   - §4.2 tables;
   - §4.3 actions;
   - §8.1 settings;
   - the dispatcher's purge (around line 2942);
   - T-13;
   - the Setup Guide configuration reference;
   - the Operator's Guide: export routine, pruning, and recovery from a lost export.
6. **Lab**:
   - a release-run step;
   - soak fault or scenario;
   - one release-run on the branch.

Each chunk: `make vuln` and `make secrets`, then a commit. All chunks go in one PR.

## 7. Settled points (2026-11-11)

- Exporting needs full access (§3.2).
- Pruning `change_requests` is out of this branch: backlog item 15.
