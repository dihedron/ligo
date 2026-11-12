# Instances managed at run time

- **Version:** 1.2 (2026-11-12), approved; 1.1 and 1.2 add the changes of chunks 1 to 3 (§15)
- **Backlog:** item 10
- **Branch:** `feature/instances`, from main at v0.3.0 (`af2d9e7`)
- **Main spec:** becomes 4.1.0 (breaking change); target release v0.4.0
- **Guides:** `.specs/ligo-instances-guides.md` (step by step, CLI and web UI)

## 1. Why

Platforms, identity provider instances and secret store instances change as often as the systems they describe: a new database, a new Vault namespace, a new directory. Today each change is an edit of `server.yaml` and a restart of every replica. Plugin types (binary, SHA-256, kind) change rarely, and a new or upgraded binary needs a restart anyway, because its SHA-256 is pinned in `server.yaml` and in SPIRE.

This feature moves **instances** into the database, managed through the API, the CLI and the web UI, with the same change control as sources and targets. **Plugin types** stay in `server.yaml`.

## 2. Decisions (the user, 2026-11-12)

| Question | Decision |
|---|---|
| Which instances | All three kinds together: platforms, identity provider instances, secret store instances. A platform's wiring names the other two, so splitting them would leave half the references in a file. |
| Who decides a change | A change request with four eyes: one `OWNER` side on the instance's jurisdiction. The requester never decides (existing rule), and the side is never `AUTO` or `DELEGATED`. Identity provider and secret store instances gain a jurisdiction. |
| What happens to today's instances | Nothing is migrated: there is no real installation. `server.yaml` loses the instance sections. Instances are created through the API; `ligo apply` takes them in manifests, in bulk, and the lab uses it to reproduce today's setup. |
| Certificates | Inline PEM only: `ca_file` becomes `ca_pem` in the three plugins. An instance names no file on the host. |

## 3. What changes in `server.yaml`

The three sections keep only plugin types:

```yaml
identity_providers:
  - type: openldap
    binary: ligo-plugin-openldap
    sha256: "…"
    instance_bounds:
      allowed_endpoints: ["ldap.corp.internal:636", "vault.prod.internal:8200"]
secret_stores:
  - type: vault
    binary: ligo-plugin-vault
    sha256: "…"
    instance_bounds:
      allowed_endpoints: ["vault.prod.internal:8200"]
platform_providers:
  - type: postgres
    binary: ligo-plugin-postgres
    sha256: "…"
    instance_bounds:
      allowed_endpoints: ["10.20.0.0/16", "vault.prod.internal:8200"]   # a network: any host and port in it
  - type: none
    builtin: true
```

1. **`instances:` and `platforms:` are refused.** The strict load already treats them as unknown keys; the error message names this spec, so that an operator with an old file knows where they went.
2. **`instance_bounds.allowed_endpoints`** (new, REQUIRED for a non-builtin type; `[]` allows none) bounds every endpoint an instance of the type may name, with the syntax of `allowed_endpoints` (§5.7): a host, `host:port`, an address or a CIDR, with no wildcards. It is the platform team's root-owned limit on where a plugin may connect and send a bootstrap credential (§9, T-22a).
3. **Role bindings** (`authorization.bindings[].platforms`, including `trusted_automation`'s, rule 13) still name platforms. A name that no ACTIVE platform has is no error, as platforms come and go: it matches nothing, and startup logs it at `WARN`.
4. Realms, the charter, role bindings, webhooks and every other section stay as they are.

The configuration's SHA-256 (`CONFIG_LOADED`) now covers types and policy only.

**Startup rules (main spec §8.2) that move.**

- **To the request (§6):** the parts of rules 1 to 6 and 8 that concern instances (names, realms, wiring, the §5.6 matrix, `match_expr`, `jwt_audience`, `allowed_source_trust_domains`, `principal_prefix`, the config schema) and the platform parts of rules 16 and 19.
- **Gone:** rule 10's references to platforms and instances (an instance in use cannot be retired, §6 rule 9), rule 11 (wiring differing from snapshots: an UPDATE of a platform affects new bindings only, INV-08), and `CONFIG_PLATFORM_CHANGED` (the request's audit records the change).
- **Kept:** types (rules 1, 7); rule 10 for secret storage strategies, a property of plugin types, with `--allow-orphaned-bindings`; rule 4's SVID checks at each `ConfigureInstances`; rule 17's checks of targets against their platform, reading the platforms in force; rule 19's report of levels and flows outside bounds, also run after a platform UPDATE (§5 rule 7).
- **`charter.source_jurisdictions`:** an entry is no longer required to be accepted by a platform, as platforms come later. A platform that accepts a trust domain needs its entry (§6 rule 4a).

## 4. The resources

Three resource kinds, with one shape. The API and manifests use camelCase, as for sources and targets.

### 4.1 Identity provider and secret store instances

```yaml
kind: SecretStore              # or IdentityProvider
metadata:
  name: vault-prod             # unique among the instances of the kind; immutable
  jurisdiction: dc/platform    # owner jurisdiction; immutable (new for these kinds)
  realm: corp                  # immutable
  displayName: Production Vault
  description: …
  contacts: [{name: …, email: …}]
type: vault                    # a type of the kind in server.yaml; immutable
svidSelector:
  matchExpr: 'path == "/ligo/plugin/vault" && hint == "vault-prod"'
  jwtAudience: ["https://vault.prod.internal"]
  allowSharedSvid: false
config: {…}                    # plugin-specific, checked against the type's schema
networkFlows: [ … ]            # §3.3
```

### 4.2 Platforms

```yaml
kind: Platform
metadata: {name, jurisdiction, realm, displayName, description, contacts}   # name, jurisdiction, realm immutable
type: postgres                                 # immutable
targetJurisdictions: ["dc/corp-prod/*"]        # default: [jurisdiction + "/*"]
namespaceTemplate: "{account}_{tenancy}"
checkExistence: true
principalPrefix: "svc_"
allowedSourceTrustDomains: [corp.internal]
rotationInterval: 24h
identityProvider: {type: openldap, instance: corp-ldap}
secretStore: {type: vault, instance: vault-prod, secretStorageStrategy: vault-static}
svidSelector: {…}
config: {…}                                    # allowed_endpoints, grantable_roles… as today
networkFlows: [ … ]
```

Every field keeps the meaning and the defaults it has in `server.yaml` today (main spec §3.4, §8.1). Only the place changes.

### 4.3 Lifecycle

- **Statuses:** `ACTIVE` and `RETIRED`. A retired instance keeps its row, because audit entries and bindings' snapshots name it, and its name is never reused, as with sources.
- **Operations:**
  - `CREATE`;
  - `UPDATE`, which needs `expectedRevision`;
  - `DELETE`, which retires the instance.
- **Changing an immutable field** means retiring the instance and creating a new one under another name.
- **A platform UPDATE may not strand a target.** Its `targetJurisdictions` must still cover every target on it, and its `namespaceTemplate` cannot change while it has targets: `422 validation-failed`.
- **Snapshots stay (INV-08).** A binding copies its platform's wiring, strategy, realm and jurisdictions at creation. An `UPDATE` of a platform affects new bindings only, and reconciliation of existing ones uses their snapshot. This includes `principalPrefix`, as AC-86 describes today.

## 5. Change control

1. **One side.** A request for an instance has one `OWNER` side on `metadata.jurisdiction`, consent `ALL`.
2. **Always a person.** The side is `HUMAN` with `ApprovalRequired` true, whatever the charter says about the jurisdiction (`required_jurisdictions`), and whatever delegation a `trusted_automation` grant holds. It is the same rule as for `PARTY:` sides (ADR-13 rule 6). The requester can never decide it (four eyes, existing rule).
3. **Who files and who decides.**
   - The same roles as for a source in that jurisdiction file a request and decide it: `operator` files, `approver` decides (§7.2.2).
   - A role binding scoped to `platforms` grants nothing on instances. Its scope names platforms, not the jurisdictions that own them.
4. **No break-glass.** Instances are not on the emergency path. A broken instance is fixed by a normal request, and a binding is revoked as today.
5. **Revalidation at approval.** Every check of §6 runs again at approval, on the definition as stored (§6.2.2 steps 2 and 3). A request filed while its wiring instance was ACTIVE fails to apply if that instance has been retired since.
6. **Audit.** These are new audit actions with the same snapshot shape as for sources:
   - `PLATFORM_CREATED`, `PLATFORM_UPDATED`, `PLATFORM_RETIRED`;
   - `IDENTITY_PROVIDER_*` and `SECRET_STORE_*`, likewise.

   The change request carries the full normalized definition and its `payloadSha256`.
7. **A tightened platform.** After an `UPDATE` that changes a platform's privilege bounds, `allowed_endpoints` or flows, the engine computes `SYSTEM_PRIVILEGE_BOUND_VIOLATIONS` and `SYSTEM_INTERCONNECT_VIOLATIONS` once the request commits. Today startup rule 19 computes them, comparing with the previous start. Existing bindings keep their snapshot and are reported, never changed.

## 6. Validation (at filing and at approval)

In order; the first failure is `422 validation-failed`, unless noted.

1. `type` is a type of the kind in `server.yaml`; `metadata.realm` is a realm in `server.yaml`.
2. `metadata.jurisdiction` follows the jurisdiction grammar. If it is account-managed, its account is registered (tenancy §7).
3. On `UPDATE`: no immutable field differs, and `expectedRevision` matches (`409`).
4. `config` validates against the type's `Describe.instance_config_schema_json`. The plugin schemas declare `additionalProperties: false`, so a key the plugin does not know, a secret pasted under a new key among them, is refused.
4a. **The checks of startup rules 4 to 6, per instance:** `svidSelector.matchExpr` compiles. Every `bootstrap_credential.jwt_audience` appears in `svidSelector.jwtAudience`. For platforms: `allowedSourceTrustDomains` ⊆ `workload_listener.accepted_trust_domains`, each with an entry in `charter.source_jurisdictions`; `principalPrefix` matches Appendix B; `targetJurisdictions` are valid patterns.
5. **Endpoints in bounds.** Every endpoint the instance names is inside the type's `instance_bounds.allowed_endpoints`: its `config.allowed_endpoints`, its `networkFlows` destinations, and the endpoints `ValidateInstance` reports (rule 8): the host and port the plugin connects to, and `bootstrap_credential.address`, where it sends the instance's JWT-SVID. The plugin reports them because only it knows how its config names them (`host` and `port`, a `url`, an `address`).
6. **Wiring** (platforms only).
   - `identityProvider` and `secretStore` name ACTIVE instances of those types, in the same realm.
   - The checks of today's `wirePlatform` also run: the identity mode is accepted, and the secret storage strategy is declared, or a single one is defaulted.
7. **SVID selection.** An instance's `svidSelector` must not resolve to an SVID that another ACTIVE instance resolves to, unless both set `allowSharedSvid` and have the same jurisdiction. This applies to every instance of the same plugin process, so of the same type and realm.
8. **The plugin's own check.** The new RPC `ValidateInstance` (§7.1) runs: the plugin parses the config and selects the SVID, without changing the instances it serves and without connecting to any endpoint of the config. It runs before rule 5, which needs the endpoints it reports. An `Unavailable` answer is `503 dependency-unavailable` and the request stays filed.
9. **Retiring (`DELETE`)** is refused with `409 instance-in-use` while:
   - an ACTIVE or DEPRECATED target is on the platform, or a binding not yet deleted names it;
   - or, for an identity provider or secret store instance, an ACTIVE platform's wiring names it.

   This is today's startup rule 10, now checked at the request.

## 7. Plugins at run time

### 7.1 Protocol version 2

- **The version.** `Describe.plugin_protocol_version` MUST be 2. ligo refuses a version 1 plugin at start: there is no compatibility before 1.0.
- **`rpc ValidateInstance(ValidateInstanceRequest) returns (ValidateInstanceResponse)`** is new, on the control service. It takes the realm, the workload socket and one `InstanceDescriptor`. The plugin parses the config, checks the bootstrap credential's shape, and selects the SVID. It returns the SPIFFE ID it would resolve and `endpoints`, every `host:port` the instance would connect to or send a credential to. It changes nothing it serves and MUST NOT connect to any of those endpoints: the bounds are checked after it answers.
- **`ConfigureInstances` is unchanged:** it sends the full set of a (type, realm), and the plugin replaces what it serves.
  - The three plugins already do so: they build the new map before swapping it.
  - The protocol now states it: on an error, the plugin MUST keep serving the previous set.
- **`pluginsdk.SelectInstances` keeps one Workload API client per process.** Today it opens a new client on every call, which would leak once configuration repeats.
- **`ca_file` becomes `ca_pem`** in openldap, postgres and vault. The value is PEM text, and `pluginsdk.LoadRoots(path)` becomes `ParseRoots(pem)`.

### 7.2 Reconciling processes

Every replica keeps its plugin processes in line with the registry (§8):

1. **On every registry change,** debounced by 2 s, compute the desired instance set of each (type, realm).
2. **New (type, realm):** spawn the process (checked binary, Describe), then configure it. Its first instance is what starts it.
3. **Changed set:** `ConfigureInstances` with the full new set. In-flight calls finish on the instance objects they hold.
4. **Empty set:** stop the process.
5. **Failure.**
   - The old set stays, and the failure is logged.
   - `ligo_plugin_reconfigure_failures_total{type,realm}` is incremented.
   - The instances the plugin did not take report `serving: false` in health.
   - The next reload, or the periodic reload, tries again.
6. **At startup,** processes start from the registry's first load. A replica with no instances starts with no plugin processes, and that is no error.
7. **Checking an instance** (§6 rules 6 and 8) uses the process of its type and realm. When none runs, because the instance is the first of its (type, realm), a process is started for the check and stopped after it; it serves nothing.
8. **Every load of the registry** hands the set to the manager, changed or not: reconcile does nothing when no set differs, and retries a set a process refused before.

The existing restart supervision (`restart_backoff`) is unchanged. A restarted process is configured with the current set.

## 8. The registry and drift

- **`internal/instances.Registry`:**
  - It holds an immutable snapshot of every ACTIVE instance, swapped atomically on reload.
  - Every former reader of `cfg.PlatformProviders`, `cfg.IdentityProviders` and `cfg.SecretStores` reads it instead.
  - It is kept fresh as the account registry is: LISTEN on `ligo_instances_changed`, plus a full reload every `server.workload_listener.resolution_cache.full_reload_interval`.
- **Drift.**
  - Each row stores `definition_sha256`, the JCS hash of its normalized definition, and a **signature** by the audit key (the Transit key `ligo-audit`, as for checkpoints) over the JCS of `{kind, name, revision, definitionSha256}`, written when a request is applied.
  - Each load checks that the definition hashes to `definition_sha256`, that the signature verifies with the cached public keys, and that the row's revision is not older than the newest revision the audit still holds for the instance.
  - The signature, not the audit, is the reference, because audit pruning (v0.3.0) removes old entries: an instance created long ago would otherwise be quarantined.
  - A row that fails, edited in the database outside ligo, is **quarantined**. It is left out of the snapshot, so it is not configured and not offered.
  - With the signing key unreachable, a load keeps the set in force rather than quarantine everything.
  - A quarantine raises `SYSTEM_INSTANCE_DRIFT`, audited once per (instance, hash), the metric `ligo_instance_drift{kind,name}` and an `ERROR` log.
  - The fix is a new request that sets the intended definition. Its apply clears the quarantine.
- **The charter no longer embeds platforms.**
  - `charter.Policy.Platforms` goes, so the charter and its SHA-256 come from `server.yaml` alone.
  - A platform change does not fail pending binding requests with `charter-changed`. They are revalidated at approval as today (§6.2.2), against the platform's current `targetJurisdictions`.

## 9. Threat model

| Id | Threat | Mitigation |
|---|---|---|
| T-22 (reworked) | An instance is changed to redirect wiring or loosen bounds. Before, this took a write to the root-owned `server.yaml`; now it takes a change request. | Four eyes in the instance's jurisdiction, never `AUTO`, `DELEGATED` or break-glass (§5). Every applied change is audited with its payload hash. Bindings keep their snapshots (INV-08). Types, their binaries and `instance_bounds` stay root-owned in `server.yaml`. |
| T-22a (new) | Two colluding or compromised approvers point an instance at a host they control. The plugin then sends the bootstrap admin credential there, or trusts that host's TLS through a `ca_pem` of their own. | `instance_bounds.allowed_endpoints` per type, root-owned: an endpoint outside it is refused at filing and at approval (§6 rule 5). A changed `ca_pem` shows in the request's diff. |
| T-22b (new) | Someone with database write access, but not ligo's, edits `instances` directly, bypassing change control. | The drift check (§8): a row whose hash or signature does not verify is quarantined and reported; the signing key is outside the database. **Residual:** a row rolled back to an earlier revision, with that revision's own signature, verifies, unless the audit still holds a newer revision. It can only restore a definition that was approved once. |
| T-22c (new) | An instance's `svidSelector` selects the SVID of another instance served by the same plugin process. Its operator then acts with the other jurisdiction's identity, for example to read that jurisdiction's bootstrap credentials. | One SVID resolves to one instance, unless every instance sharing it sets `allowSharedSvid` and has the same jurisdiction (§6 rule 7), checked at filing, at approval and at each configuration. |
| T-22d (new) | A file path in an instance's config makes the plugin read a host file of the operator's choice. | No file paths: `ca_pem` replaces `ca_file` (§7.1). The schemas declare no path keys. |
| T-22e (new) | A secret is pasted into an instance's config, where it would be stored, audited and shown in diffs. | `additionalProperties: false` in every plugin schema. Bootstrap credentials stay references (`bootstrap_credential`), as today. The guides say so. |
| T-22f (new) | Rapid changes make every replica reconfigure its plugins without pause (denial of service). | Changes go through four-eyes requests and the API rate limits. Reconfiguration is debounced, 2 s. The number of processes is bounded by types × realms. |

Rows T-22 to T-22f replace the T-22 row of the main spec. The "Read configuration" row of the privilege table (§13) stays, for types.

## 10. API, CLI and web UI

### 10.1 API (OpenAPI `admin.v1alpha1`)

| Path | Verbs | Notes |
|---|---|---|
| `/v1/admin/platforms` | GET, POST | POST files a `CREATE` request: `202` with the request, `201` never (four eyes). |
| `/v1/admin/platforms/{name}` | GET, PUT, DELETE | PUT needs `expectedRevision`. DELETE retires the platform. |
| `/v1/admin/identity-providers`, `/{name}` | as above | |
| `/v1/admin/secret-stores`, `/{name}` | as above | |
| `/v1/admin/{kind}/{name}/history` | GET | The audit entries of the instance, as for sources. |

**Visibility.**
- Any viewer sees the summary `GET /v1/admin/platforms` gives today (§3.4): name, type, realm, jurisdictions, display data, flows, health and privilege bounds.
- The full definition (`config`, `svidSelector`, wiring) is visible only to people holding `operator` or `approver` on the instance's jurisdiction. They file and review it, and it holds references but no secrets.
- The same rule covers change requests: their payload is shown to the deciders, as today.

### 10.2 CLI

- **`ligo apply -f`** takes three more kinds: `IdentityProvider`, `SecretStore` and `Platform`.
  - It files them before sources, targets and bindings, in that order.
  - Create and update follow the existing manifest rule: no `expectedRevision` means create.
  - A platform whose wiring instance is still a pending request is refused by validation. `ligo apply` reports it and goes on with the rest, and a second run after approval files it. The guides show the two runs.
- **`ligo list platforms|identity-providers|secret-stores`, `ligo get <kind> <name>` and `ligo delete <kind> <name>`** join the existing nouns.
  - `ligo platform list|show|schema` stays.
  - `ligo platform history <name>` is new, likewise for the other kinds.
- Approval uses the existing `ligo change-request approve` and `review`.

### 10.3 Web UI

- **The Platforms page** gains create and edit, through a form with the metadata fields and a YAML or JSON editor for `config`, checked against the type's schema on submit.
- **New pages:** identity providers and secret stores, with the same form.
- Requests are reviewed on the existing change request pages, with the diff.

## 11. Data (migration 001, edited in place)

```sql
CREATE TYPE instance_kind AS ENUM ('PLATFORM','IDENTITY_PROVIDER','SECRET_STORE');
ALTER TYPE resource_type …  -- edited in place: 'SOURCE','TARGET','BINDING','PLATFORM','IDENTITY_PROVIDER','SECRET_STORE'

CREATE TABLE instances (
    id                 UUID PRIMARY KEY,                 -- UUIDv7
    kind               instance_kind NOT NULL,
    name               resource_name NOT NULL,
    type               VARCHAR(63) NOT NULL,
    realm              VARCHAR(63) NOT NULL,
    jurisdiction       jurisdiction_path NOT NULL,
    status             VARCHAR(8) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','RETIRED')),
    revision           BIGINT NOT NULL DEFAULT 1,
    definition         JSONB NOT NULL,                   -- normalized (§4)
    definition_sha256  CHAR(64) NOT NULL,                -- JCS
    key_id             VARCHAR(128) NOT NULL,            -- the audit key's version
    signature          TEXT NOT NULL,                    -- over {kind, name, revision, definitionSha256} (§8)
    created_at, updated_at, created_by, updated_by …,
    UNIQUE (kind, name)
);
```

- **Triggers:**
  - `kind`, `name`, `type`, `realm` and `jurisdiction` are immutable;
  - a `RETIRED` row is never changed;
  - `trg_instances_notify` notifies `ligo_instances_changed`.
- **Grants:** `ligo_app` gets `SELECT, INSERT, UPDATE`, and no `DELETE`.
- **`change_requests`:**
  - `chk_cr_jurisdiction_columns` gains the row for the three kinds: `owner_jurisdiction` and `realm` set, the others NULL;
  - `chk_system_kinds` keeps `BREAK_GLASS` to `BINDING` and `SOURCE`.
- **Snapshot columns.** `targets.platform_type`, `platform_jurisdiction` and `realm`, and the binding snapshot columns, are unchanged. They keep the platform's name as text, with no foreign key, as today.

## 12. Tests first

- **`internal/instances`, unit tests:**
  - normalization and defaults;
  - immutable fields;
  - the endpoint bounds, matched and refused, including a flow destination and a config endpoint;
  - wiring checks;
  - SVID-sharing rules;
  - JCS hashing.
- **Integration tests on docker PostgreSQL:**
  - create, approve, update and retire each kind;
  - the requester refused as decider;
  - `AUTO` never given, even for a jurisdiction outside `required_jurisdictions`;
  - a `trusted_automation` caller gets no `DELEGATED` side;
  - retire refused while referenced;
  - a direct `UPDATE instances` as superuser is quarantined and audited, and a new request clears it;
  - LISTEN updates a second registry.
- **`pluginmgr`, with `testdata/testplugin`:**
  - add, change and remove instances at run time;
  - a lazy spawn and a stop;
  - a failed `ConfigureInstances` keeps the old set;
  - the debounce;
  - a process restart configured with the current set.
- **Plugins:**
  - `ValidateInstance` in the three plugins and the builtins;
  - `ca_pem` parsing;
  - one Workload API client across calls.
- **API and CLI:**
  - `TestINV11Routes` covers the new mutating routes;
  - visibility, summary against full definition;
  - `ligo apply` ordering and the pending-wiring report.
- **Startup:** `server.yaml` with `instances:` or `platforms:` is refused with the pointer to this spec; an unknown platform in a role binding gives a `WARN`.
- **Fuzzing:** a fuzz target over manifest parsing with the new kinds, and one over definition normalization.
- **Lab** (`lab.sh`):
  - `server.yaml` keeps types only;
  - `test/lab/instances.yaml` holds today's instances;
  - after `up`, the lab applies it as one LDAP user and approves as another, so every existing suite runs on instances made through the API.
  - New `serve test-instances`:
    - a platform added and a target bound on it, with no restart on any replica;
    - a platform's bounds tightened, and the violations reported;
    - a retire refused while in use;
    - an endpoint outside the bounds refused;
    - a drift detected and cleared.

    It joins the release-run.

## 13. Chunks

Each chunk is a stop point: tests and code, then `make lint`, `make vuln` and `make secrets`, then a commit on the user's word.

| No. | Content |
|---|---|
| 0 | This spec, the guides file, and the backlog row |
| 1 | Plugin protocol v2: `ValidateInstance`, `ca_pem`, one Workload API client, in the SDK, the three plugins and the builtins |
| 2 | Data and core (one commit, as callers cannot compile apart): migration, `internal/instances` (registry, service, drift), `server.yaml` types only, every consumer on the registry, charter without platforms, startup rules moved to the request (§3) |
| 3 | Plugin manager reconcile (§7.2) |
| 4 | API and CLI (§10.1, §10.2), OpenAPI |
| 5 | Web UI (§10.3), htmx check |
| 6 | Docs: main spec 4.1.0 and its changelog, Setup Guide, Operator's Guide (procedures, drift incident), Architecture (threat model), README, configuration reference |
| 7 | Lab: `instances.yaml`, the approval step, `serve test-instances`, release-run on OpenBao and Vault |

## 14. Out of scope

- **Plugin types at run time.** A new binary still needs `server.yaml`, SPIRE entries and a restart.
- **SPIRE registration entries for instance SVIDs.** The SPIRE operator creates them. Without one, `ValidateInstance` fails, the request is refused, and the guides say which entry to create.
- **Realms at run time.**
- **Terraform** (backlog item 8). The rule in §5.2, never `DELEGATED`, will need revisiting when that item is designed.

## 15. Changes since 1.0

| Version | Section | Change |
|---|---|---|
| 1.1 | §6 rule 5, §7.1 | `ValidateInstance` reports the instance's endpoints, `bootstrap_credential.address` included; no `x-ligo-endpoint` schema annotation (chunk 1). |
| 1.1 | §8, §11, T-22b | Rows are signed by the audit key; the drift check verifies the signature, not the audit entry, which pruning may have removed (chunk 2). |
| 1.1 | §3 | `instance_bounds` takes the `allowed_endpoints` syntax, with no wildcards; the startup rules that move, go and stay are listed; `source_jurisdictions` entries need no platform (chunk 2). |
| 1.1 | §4.3 | A platform UPDATE may not strand a target (chunk 2). |
| 1.1 | §8 | The registry reloads every `resolution_cache.full_reload_interval`, as the account registry (chunk 2). |
| 1.2 | §7.2 | A process started for the check of a first instance; reconcile at every load, so refusals are retried (chunk 3). |
