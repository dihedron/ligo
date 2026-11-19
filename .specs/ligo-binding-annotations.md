# A description and annotations on each binding

- **Version:** 0.1 (2026-11-19), approved by the user in plan mode
- **Backlog:** item 25 (recorded as "metadata"; renamed `annotations`, see §2)
- **Branch:** `feature/binding-annotations`, from `feature/python-sdk` (it carries the backlog and the client SDK's flow testing); rebased onto main when that merges
- **Main spec:** 4.1.1 becomes 4.2.0 (breaking: two field renames, two fields on the workload API)

## 1. Why

A workload that reads its bindings sees names, access level, platform and credentials strategy, and nothing that tells a person or a program what the binding is for. The admin side already has a text and a map on each binding (`purpose`, `labels`), but they never reach the workload. Operators want to say what a binding is (a description) and to attach their own keys (a change number, a team, a cost centre), and want the workload to read both and show them or act on them.

## 2. Decisions (the user, 2026-11-19)

| Question | Decision |
|---|---|
| New fields or the existing `purpose` and `labels` | Rename and expose: `purpose` becomes `description`, `labels` becomes `annotations`; no compatibility code (AGENTS rule 8, before 1.0.0) |
| How a change is made | As today: a change request with the consent of all sides, a new revision, provisioning again. The text a workload sees is what was approved |
| The name of the map | `annotations`, not `metadata`: the admin API's resource envelope already uses `metadata` (id, name, realm, createdAt), so the key would clash in the admin response. The word is the Kubernetes one for free-form key/value data (the user, 2026-11-19) |
| Who sees them | The admin API and UI, and the workload API (REST and gRPC) and the Go SDK; the Python SDK takes them when it resumes |

## 3. The contract

### 3.1 Fields

| Field | Type | Meaning |
|---|---|---|
| `description` | string, optional | What the binding is for, in plain text |
| `annotations` | object, string keys to string values, optional | Operator-defined keys; ligo gives them no meaning |

Neither is interpreted by ligo, nor ever used to decide access. They are not a place for secrets (T-M1).

### 3.2 Limits

Checked when a change request is filed (and again when it is applied), on the admin API, the UI, a manifest and a break-glass change alike. A violation is a `400` that names the field.

| Field | Rule |
|---|---|
| `description` | at most 4096 runes; no control characters except newline and tab; valid UTF-8 |
| `annotations` | at most 32 entries; at most 8 KiB for all keys and values together |
| an annotation key | 1 to 63 characters, `[A-Za-z0-9._/-]`, starting with a letter or a digit |
| an annotation value | at most 256 runes; no control characters; valid UTF-8 (it may be empty) |

The database enforces what it can: `description` with `length(description) <= 4096`.

### 3.3 Where they appear

- **Admin API** (`api/openapi/admin.v1alpha1.yaml`): `BindingSpec` (request) and `Binding` (response) rename `purpose` to `description` and `labels` to `annotations`, with `maxLength`, `maxProperties` and `additionalProperties: {type: string}`. The CLI's `binding show` prints them; manifests (`ligo apply`, kind `Binding`) take them. Binding `list` columns do not change.
- **UI:** the binding forms (wizard, edit, break-glass) have a description area and a key/value editor (the existing `pairs` input), and the binding page shows both, escaped.
- **Workload API**, the binding item of `GET /v1/bindings` and the gRPC `WorkloadBinding`: `description` (string, omitted when empty) and `annotations` (object, omitted when empty); proto fields 12 and 13 (`string description = 12; map<string,string> annotations = 13;`). They are in the ETag body like every other field, so a change of text changes the ETag and a watching client sees the revision's change.
- **Go SDK** (`pkg/client`): `Binding.Description string` and `Binding.Annotations map[string]string`. The map is a copy: the caller may change it, and no other binding or call shares it.
- **Not carried:** audit entries and webhook payloads (they carry no binding body today and keep that); `v_active_bindings` is the only new reader.

### 3.4 What the workload sees, and when

The workload API serves the active snapshot of a binding, through `v_active_bindings`. `description` and `annotations` are read from the binding's own columns, which the apply step writes in the same transaction that approves the revision (`revise`). So the text of an approved revision is served from the moment the revision is applied, before provisioning of that revision ends, and never before the approval. The notify trigger on `bindings` fires on a change of either column, so every replica reloads its cache.

### 3.5 Storage

Migration `002_binding_description_annotations.sql` (a new file: existing databases migrate):

- `ALTER TABLE bindings RENAME COLUMN purpose TO description; RENAME COLUMN labels TO annotations;` and the check on `description` becomes `<= 4096`;
- `v_active_bindings` gains `description` and `annotations`;
- the `WHEN` clause of `trg_bindings_notify_update` adds both columns.

The column `flows.purpose` (DATA, CREDENTIALS, DISCOVERY) is another thing and does not change.

## 4. Threat model

| ID | Threat | Mitigation |
|---|---|---|
| T-M1 | An operator puts a secret in the text, and now every workload that matches the binding reads it, and so does anyone who reads the admin API | The guides and the forms say so; the value is plain text for everyone the binding reaches; no feature stores secrets there. Residual: ligo cannot recognize a secret |
| T-M2 | The client receives text it did not write: markup, a prompt, a command | It is data. The UI escapes it (templates, no raw HTML); the SDKs never interpret it and the Go and Python documentation say the same; limits on characters keep control characters out of terminals |
| T-M3 | Size or count abuse: a huge description or thousands of keys, to slow the cache, the ETag or the clients | The limits of §3.2, checked on the server; the workload API's body cap is unchanged |
| T-M4 | A change reaches workloads without approval | It goes through a change request: the approval hash covers the whole `Binding` payload (`changerequests.Hash`), consent is `ALL`, and the text is served only after it is applied (§3.4) |
| T-M5 | The text lands in logs or audit entries | Unchanged: no binding body in audit or webhooks; the server logs names, never the text; the SDK does not log the fields |
| T-M6 | A key that looks like an instruction to a tool that reads annotations (`ligo.io/...`) | ligo reserves nothing and interprets nothing; a client that acts on a key is the operator's own contract with its workloads |

## 5. Tests (written first)

| ID | What |
|---|---|
| BM-1 | `description` and `annotations` validation: every limit, at the edge and one over; control characters; invalid UTF-8; key charset; empty value |
| BM-2 | The admin API rejects a violation with a `400` that names the field; a manifest and a break-glass change too |
| BM-3 | A binding created with both reads them back from the admin API, the CLI's `show` and the UI page (escaped) |
| BM-4 | A text-only change is a change request with consent `ALL`; the old text is served until it is applied and the new after, and the revision rises |
| BM-5 | The workload API (REST and gRPC) carries both, omits them when empty, and the ETag changes when either changes |
| BM-6 | A replica's cache reloads after a text-only change (the trigger) |
| BM-7 | Migration 002 on a database with data keeps the old `purpose` and `labels` under the new names; the check is 4096 |
| BM-8 | The proto block in this repository's main spec and `workload.proto` agree (the contract test) |
| BM-9 | The Go SDK decodes both over REST and gRPC; the map is a copy |
| BM-10 | Fuzz: the validator never panics and accepts exactly what the rules say |
| BM-L1 | Lab: `lab.sh serve test-sdk` binds with a description and annotations and the SDK's client reads them |

## 6. Chunks

| # | Chunk |
|---|---|
| 1 | This spec; the main spec 4.2.0 (§3.5, §3.6, mutability table, SQL, view, proto block, REST, UI, threat inputs); the client SDK spec; backlog |
| 2 | Tests red (BM-1, 2, 7, 8), migration 002, domain, validation, admin API and OpenAPI, `make generate` |
| 3 | Workload API, proto and `make proto`, resolution, ETag; Go SDK (BM-3 to BM-6, BM-9) |
| 4 | CLI, UI, manifests; fuzz and lab (BM-10, BM-L1) |
| 5 | Docs: Developer's Guide, Setup Guide, README Status, Architecture guide threat rows, Operator's Guide (migration 002); the Python SDK spec's `Binding` |
| 6 | The Terraform provider (after the next ligo release: it pins ligo v0.7.0), PR, merge on the user's word |
