# Change request pruning

- **Version:** 1.0 (2026-11-11), approved
- **Backlog:** item 15
- **Branch:** `feature/cr-pruning`, from `feature/pruning` (audit export and pruning, `.specs/ligo-pruning.md`); rebased onto main once that merges
- **Main spec:** 4.0.9

## 1. Why

`change_requests` only grows, as `audit_log` did. Every request stays, with its sides and its payload, whatever its outcome: approved, rejected, withdrawn, expired or failed. Audit pruning leaves them all.

## 2. Decisions (the user, 2026-11-11)

| Question | Decision |
|---|---|
| A live binding's visible jurisdictions come from the `PARTY:` sides of all its requests | Stored on the binding instead: a `party_jurisdictions` column, kept up to date when a request is filed |
| When may a closed request go | After its own retention, and only once every audit entry naming it is pruned: so an exported audit file covers it |
| The request's payload, in no audit entry | Added to the audit export, and checked by offline verification against `payload_sha256` |

## 3. What ties a request down today

1. **Visibility.** `internal/bindings/views.go`, `internal/catalog/catalog.go` and `internal/server/adminhttp/ops.go` give a binding the jurisdictions of the `PARTY:` sides of every request of the binding, of any status. Deleting an old request would narrow who sees a live binding.
2. **Foreign keys.**
   - `bindings.break_glass_cr_id`: the open break-glass change of a binding.
   - `change_requests.reverts_cr_id`: a revert's break-glass change.
   - `change_requests.depends_on_cr_id`: a binding create's inline source create.
   - `change_request_sides` cascades from its request.
3. **Audit references.** `audit_log.change_request_id` has no foreign key, but the audit API and the UI read a request through it.
4. **Grants.** `ligo_app` holds `DELETE` on `change_requests`, which no code uses.

## 4. The design

### 4.1 Parties on the binding

- A new column: `bindings.party_jurisdictions jurisdiction_path[] NOT NULL DEFAULT '{}'`.
- Two triggers keep it, in the transaction that writes the request, whatever code path does: a `PARTY:` side inserted for a request of an existing binding adds its jurisdiction; a binding request whose `resource_id` is set (a `CREATE` applied) adds the jurisdictions of its `PARTY:` sides. That keeps the current rule, every request of any status, without reading the requests.
- The three queries in §3.1 read the column instead.
- Migration 001 is edited in place (no compatibility before 1.0).

### 4.2 Settings

```yaml
storage:
  change_requests:
    retention: 0s   # 0: keep every request (default); else at least 24h
```

### 4.3 What a prune deletes

On the audit loop's daily prune pass, after the audit prune, requests that are all of:

1. closed: status other than `PENDING`;
2. decided more than `retention` ago (`decided_at`);
3. named by no audit entry left in `audit_log` (those entries were pruned, so an export holds them);
4. referenced by no binding's `break_glass_cr_id`, and by no request that stays (`reverts_cr_id`, `depends_on_cr_id`): a chain goes as a whole or not at all.

Their sides go with them (`ON DELETE CASCADE`). `SYSTEM_CR_PRUNED` (actor `system:audit`) records the count, the cut-off and the retention. The pass runs after the audit prune of the same day, so the requests whose entries it just deleted can go.

### 4.4 Deleting

- `ligo_app` loses `DELETE` on `change_requests`.
- A `SECURITY DEFINER` function `change_requests_prune(older_than TIMESTAMPTZ) RETURNS BIGINT`, owned by the migrator, applies the rules of §4.3 itself, so `ligo_app` cannot delete a request any other way. It refuses an `older_than` later than 24 hours ago.

### 4.5 The audit export carries the requests

- `ligo audit export` adds one line per request named by an exported entry, after the checkpoints and before the entries: `{"kind":"change_request", "changeRequestId", "row":{...}, "sides":[...], "payloadSha256"}`. The key is `changeRequestId`, not `id`: entry lines use `id` for their number.
- The export's own entries are the reason the request is in it; a request named by no exported entry is not.
- `ligo audit verify --file` checks each request's payload against its `payloadSha256` (JCS, SHA-256), and that each request is named by an entry of the file.
- The request lines are not part of the hash chain or the checkpoints. They are as trustworthy as the database they came from, and the file's SHA-256 recorded in `audit_exports` fixes them from then on. The spec and the Operator's Guide say so.

## 5. Tests first

- **Unit:** the export's request lines and their verification, including a changed payload.
- **Integration, docker PostgreSQL:**
  - `party_jurisdictions` set on filing, and the three readers;
  - each rule of §4.3 keeping a request, and one request that qualifies going, with its sides;
  - `ligo_app` refused a `DELETE`;
  - the export round trip with requests.
- **Lab:** `serve test-audit` grows a request prune after the audit prune.

## 6. Chunks

1. Parties on the binding.
2. Schema, `change_requests_prune` and the grants.
3. Requests in the export, and their offline check.
4. The prune pass, the setting, `SYSTEM_CR_PRUNED`.
5. Docs and main spec 4.0.9.
6. Lab.

## 7. Settled points (2026-11-11)

- `ligo_app` loses `DELETE` on `change_requests`; sides, never removed until now, go with their request once archived.
- A metric, `ligo_change_requests_pruned_total`.
- Retired sources, targets and bindings stay for ever (001). Not in this branch.
