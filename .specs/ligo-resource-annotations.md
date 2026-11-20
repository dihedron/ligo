# Annotations on sources and targets

- **Version:** 0.1 (2026-11-20), approved by the user in plan mode
- **Backlog:** item 30
- **Branch:** `feature/resource-annotations`; released as v0.12.0; then `terraform-provider-ligo` follows (its three resources)
- **Follows:** `.specs/ligo-binding-annotations.md` (bindings, v0.10.0)
- **Main spec:** 4.2.0 becomes 4.3.0 (breaking: a field and a filter renamed)

## 1. Why

Since v0.10.0 a binding has a `description` and an `annotations` map. A source and a target have a `description` and a `labels` map, which is the same free-form key/value data under the old name. Three resources with two names for one thing make the CLI, the UI, the API and the Terraform provider inconsistent. The user (2026-11-20) chose to give sources and targets the names of bindings.

## 2. Decisions (the user, 2026-11-20)

| Question | Decision |
|---|---|
| Rename or add | Rename: `labels` becomes `annotations` on sources and targets. Not both: one map per resource |
| The filter | `label=key=value` becomes `annotation=key=value` (admin API query parameter, CLI `--annotation`), on sources, targets and the catalog; it keeps matching one key to one value |
| The text search | `q` matches the name, display name, description and annotations, as it matched labels |
| Compatibility | None (AGENTS rule 8, before 1.0.0): the old name is refused by the admin API (unknown field) and the old flag is gone |
| Limits | The same as a binding's (§3.2 of the binding spec), one checker for all three (`internal/annotations`): `description` at most 4096 runes, no control characters but newline and tab; at most 32 annotations, 8 KiB in all; a key 1 to 63 characters of `[A-Za-z0-9._/-]` starting with a letter or a digit; a value at most 256 runes without control characters. Checked when a change request is filed, on the admin API, the UI and a manifest alike; a violation is a `400` naming the field (the user, 2026-11-20) |
| Workload API and SDKs | Unchanged: a workload never saw a source's or a target's labels |
| How a change is made | As today: a change request; the diff field is named `annotations` |

## 3. The contract

- **Database:** migration `003_source_target_annotations.sql`: `ALTER TABLE sources RENAME COLUMN labels TO annotations`, and the same for `targets`; every view, function and trigger that names the column is recreated.
- **Admin API** (`api/openapi/admin.v1alpha1.yaml`): `labels` becomes `annotations` in the source and target schemas, requests and responses, and in the catalog entry; the query parameter `label` becomes `annotation`. The admin client is regenerated.
- **CLI:** `ligo source|target|catalog list --annotation key=value` (repeatable, as `--label` was); manifests (`apply`, kinds `Source` and `Target`) use `annotations`; `show` prints them.
- **UI:** the source and target forms and pages, and the catalog filter, say "annotations".
- **Not changed:** the audit log carries what it carried; platform instance and plugin schemas have no labels.

## 4. Threat model

| ID | Threat | Mitigation |
|---|---|---|
| T-A1 | Annotation text of a source or a target is rendered unescaped in the UI, or taken as instructions by a reader or a tool | Data only, as for bindings (T-M1, T-M2): the UI escapes it (html/template), the CLI prints it as text, nothing in ligo interprets a key or a value |
| T-A2 | Secrets are put in annotations | Documented as not a place for secrets, as for bindings; the audit log is not extended |
| T-A3 | A catalog reader sees the annotations of a target outside its visibility | The catalog applies the same visibility rules to the whole entry; the rename does not change which entries a caller sees |

## 5. Tests (written first)

| ID | Test |
|---|---|
| RA-1 | Migration 003 on a database with data: the old labels of sources and targets are readable as annotations; a second run changes nothing |
| RA-2 | The admin API creates and returns `annotations` for a source and a target; a body with `labels` is refused |
| RA-3 | The `annotation` filter finds a source, a target and a catalog entry by key and value; `q` finds one by an annotation text |
| RA-4 | A change request on a source or a target shows `annotations` in its diff |
| RA-5 | The UI forms round trip annotations and escape their text |
| RA-6 | The CLI `--annotation` filters; a manifest with `annotations` applies |
| RA-8 | A source and a target are refused with a description over 4096 runes or with a control character, 33 annotations, a bad key or a value over 256 runes; they accept a key such as `example.org/change-id`. The shared checker has the binding tests (BM-1, BM-10) and the fuzz |
| RA-7 | Lab: the e2e tests that file sources and targets pass |

## 6. Plan

Spec, tests, migration and Go domain (`internal/sources`, `internal/targets`, `internal/catalog`), the admin API and its client, the CLI, the UI, the lab and the docs; then v0.12.0; then the provider (`go get`, the three resources, docs, tests).

## 7. Out of scope

Selectors apart from annotations (a `labels` of their own, if one is ever needed); exposing source or target annotations to workloads.
