# The Go admin API client

- **Version:** 0.3 (2026-11-14), approved by the user on 2026-11-14; implementation may start (chunk 1). 0.2 reconciled 0.1 with the Go client SDK (§0) and the contract; 0.3 adds the instances (§3.4a), starts the contract work (§3.4b) and settles §8
- **Backlog:** item 8 (Terraform and OpenTofu provider) and item 11 (MCP server), which both need it
- **Branch:** `feature/adminclient`, in the main checkout, cut from `feature/client-sdk` and rebased onto `main` on 2026-11-14, after the client SDK was merged (v0.5.0); its PR is opened when the chunks are done
- **Decisions of 2026-11-14 (the user):** the package is `pkg/adminclient` in this module; its types and calls are generated from `api/openapi/admin.v1alpha1.yaml` with `oapi-codegen`, under a thin hand-written layer; the provider is a separate repository on `terraform-plugin-framework`.
- **Follow-up specs:** the provider (`ligo-terraform-provider.md`, in its repository's design; the server changes it needs, such as managed-by-automation resources, are decided there) and the MCP server (`ligo-mcp-server.md`). This spec covers only the client they share.

## 0. Fit with the Go client SDK (backlog item 7)

`pkg/client` (`.specs/ligo-client-sdk.md`) is the SDK of a **workload**: it calls the workload API (port 8443) with the workload's SVID and reads credentials. `pkg/adminclient` is the client of the **admin API** (port 9443) for tools that file and follow change requests. They share no operations and no types; they share a few rules, which this spec takes over from the SDK as it was built:

| Rule | In `pkg/client` | In this spec |
|---|---|---|
| Server verification | `ServerID` against the SPIFFE bundle, TLS 1.3, no option to skip | §3.2, the same, plus `RootCAs` for LDAP-Basic users |
| Redirects | A store's redirect is never followed | T-A1, the same |
| Body limit | 8 MiB | T-A3, the same |
| `Retry-After` | Honoured, up to one hour | §3.4, the same floor and ceiling |
| Secret values | `Credential` prints no password | T-A2, the same idea for the Basic password |
| Documentation | The Developer's Guide, Part 1 (workloads) and Part 2 (plugins) | §6: a new **Part 3, "Automating ligo"**, for the developers of tools |

- **Names.** Two packages named `client` and `adminclient` are easy to confuse: each package comment and each guide chapter says which API it calls. No rename is proposed: `pkg/client` is the SDK's settled name, and `adminclient` says what the other one is. Say so now if you prefer another pair before `pkg/client` is released.
- **Shared code.** The helpers both need (a limited body reader, a redirect refusal, a `Retry-After` parser, a redacting string type) are each a few lines. They are copied, not shared, until a third user needs them (§8, point 4).
- **Order.** The client SDK is merged first: this spec's chunk 6 edits the Developer's Guide, which exists only on that branch.

## 1. Why

Three programs call the admin API: the `ligo` CLI, the Terraform/OpenTofu provider and the MCP server. Only the CLI has a client, `internal/client`, which is private to this module and mixes API calls with printing and terminal prompts. A third party, the provider and the MCP server included, must be able to import one client, so that authentication, server verification, error mapping and the rules of change requests are written once and tested once.

## 2. Scope

In: `pkg/adminclient`, a Go package of this module, for every operation of `admin.v1alpha1.yaml` except the human decisions of §8 point 2, instances included (§3.4a); the CLI moved onto it.
Out: the provider, the MCP server, printing (stays in the CLI), prompts, new server routes, clients in other languages.

## 3. Design

### 3.1 Two layers

| Layer | Package | Content |
|---|---|---|
| Generated | `pkg/adminclient/internal/gen` | `oapi-codegen` output: one type per schema, one method per `operationId`. Checked in; `make generate` rebuilds it; CI fails when the checked-in code differs from the YAML. Not importable: its names are not part of the API. |
| Hand-written | `pkg/adminclient` | `Client`, `Config`, authentication, server verification, errors, pagination, change-request helpers, and the exported types and methods that wrap the generated ones. |

The exported API names its own types (aliases or small structs over the generated ones) so that a change of generator, or of a generated name, does not break importers.

### 3.2 Configuration and authentication

`Config` (no flags, no environment: those belong to the CLI):

- `ServerURL`: an `https://` URL; anything else is refused.
- Server verification: either `RootCAs` (a `*x509.CertPool`), or an `X509Source` and `ServerID` (the SPIFFE ID of `ligo`, verified against the source's bundle, as `pkg/client` does). One of them is required; there is no option to skip verification.
- Authentication: either an `X509Source` (the client SVID, mTLS) or `BasicAuth{Username, Password}` (the server's `allow_basic_auth`). Exactly one. The password is a `string` the caller supplies: the package never prompts, never reads a file and never logs it.
- `Logger` (`*slog.Logger`, default `slog.Default()`), `HTTPClient` (optional, for proxies and tests; its TLS configuration is replaced by the package's, never merged), `UserAgent`.

### 3.3 Operations

One method per operation, `ctx` first, named from the `operationId` (`ListBindings`, `CreateSource`, `GetChangeRequest`). Lists return an iterator (`iter.Seq2[T, error]`) that follows `nextPageToken`, and a `ListPage` form for one page. Resources keep their `revision`.

### 3.4 Change requests

Every mutation of the API files a change request. The client does not hide that:

- A mutation returns the `ChangeRequest` the server answered with, never the resource as if it had changed.
- **The contract gaps are closed first (chunk 1, §3.4b).** The change request's `status` had no enum, so the terminal states of `WaitChangeRequest` would have been a copy in Go; and since backlog item 10 the `resourceType` enum of `listChangeRequests` lacked `PLATFORM`, `IDENTITY_PROVIDER` and `SECRET_STORE`. Both are fixed, with tests. The wider gap, that most requests and responses are still `type: object`, is the work of chunk 1.
- Updates take `expectedRevision`; a missing one is an error before any call.
- `WaitChangeRequest(ctx, id, WaitOptions)` polls until the request is in a terminal state (`APPLIED`, `REJECTED`, `WITHDRAWN`, `EXPIRED`, `FAILED`) or the context ends. Polling has a floor of 1 s, jitter, back-off after failures, and honours `Retry-After`. The terminal states (`APPLIED`, `REJECTED`, `WITHDRAWN`, `EXPIRED`, `FAILED_TO_APPLY`: every `ChangeRequestStatus` but `PENDING`) and the optional wait for a binding to be `ACTIVE` come from the API's enums, not from a copy.
- `approvalReference` and `automationContext` (delegated approval, ADR-11) are fields of the mutation request, passed through unchanged. The client never approves, declines, ratifies or reverts anything by itself.

### 3.4a Instances: platforms, identity providers, secret stores

Decision of 2026-11-14 (the user): the client exposes the filing of instances, as well as reading them. The Terraform provider (the sibling session) uses them in two steps: first as **data sources**, which only read, then as **resources**, which file creations, changes and deletions. The client therefore offers the instance operations in the same two steps, and the two groups are separate files, so that the first step ships without the second.

| Step | Operations (all three kinds: `/v1/admin/platforms`, `/identity-providers`, `/secret-stores`) | Used by |
|---|---|---|
| Read | list, get, audit (`ListPlatforms`, `GetIdentityProvider`, `PlatformAudit`, …) | data sources |
| Write | create, update (`expectedRevision`), delete, each filing a change request (`CreatePlatform`, `UpdateSecretStore`, `DeleteIdentityProvider`, …) | resources |

- **A write is a filing.** An instance change needs one `OWNER` approval on the instance's jurisdiction, never `AUTO` or `DELEGATED` (`.specs/ligo-instances.md` §5). The client returns the `ChangeRequest`; a Terraform resource that must see the instance in force waits with `WaitChangeRequest`, or says that the plan is pending approval. `WaitChangeRequest` returns `APPLIED`, and the provider then reads the instance. The client does not approve, so a provider without a second person's approval does not complete; that is the intended four eyes, and the provider's spec says how it reports it.
- **What a reader sees.** A reader sees an instance's summary and its health; only a person who may file or decide on its jurisdiction also gets `revision` and `definition` (`GET`). A data source documents which attributes it can fill for whom. The client exposes `Revision` and `Definition` as optional and says why when they are absent.
- **Definitions are typed.** The `definition` of each kind (`internal/instances.Definition`: metadata, type, `config`, `svidSelector`, wiring, `networkFlows`, …) is a schema of the OpenAPI document (§3.4b), so that the provider's resources can be typed and its plans compared. `config` stays a free JSON object: its schema is the plugin's, which `ligo` serves in the plugin's `Describe` (a read method on the client in a later step, so the provider can validate a plan).
- **Idempotent filing is the provider's.** The CLI's `ligo apply` creates an instance or updates it at its current revision; the client offers the primitives (get, create, update with `expectedRevision`) and no apply. Plan and apply logic is the provider's.
- **No secrets in or out.** An instance names a bootstrap credential, it does not hold one (`ligo-instances.md` T-22). The client never logs a definition, in case `config` holds anything a user put there.

### 3.4b The contract before the code

The OpenAPI document is the source of the client's types, so it must say what the server sends. Done on 2026-11-14 (chunk 1 begins with it): the change request (`ChangeRequest`, `Side`, `BreakGlass` and the enums `ResourceType`, `ChangeRequestStatus`, with `listChangeRequests` and `getChangeRequest` typed), and two tests in `internal/server/adminhttp/openapi_test.go`: `TestOpenAPIEnums` (the document's enums equal the database's) and `TestOpenAPIChangeRequest` (what the server sends satisfies the schema, as a read, a filing and a list). Typed on the same day, each with a test in `openapi_resources_test.go` that what the server sends (and what a caller writes) satisfies the schema: sources, targets and their audit entries, bindings with stages, platforms, the three instance kinds and their `definition` (`InstanceDefinition`), the catalog, accounts, and the resource of `Filed` (a source, a target, a binding or null); the lifecycle, phase, operation and stage enums are held equal to the database's. Platform-specific parts (`definition`, `grants`, `parameters`, `spec`, `auth`, `config`) stay free-form objects by design: their schemas come from the plugins. Still untyped, to type with the same two kinds of test: `testSourceRegex`, the results of `revokeTargetBindings`, `retryBinding`, `rotateBinding`, and of the decisions (`approve`, `decline`, `withdraw`, `ratify`, `revert`), `listBreakGlass`, `putMaintenance`, `recordAuditExport`, `verifyAudit`, `listExecutors`, `recoverExecutor`. A generated client over a document that says `type: object` for everything would give `map[string]any`, which is no client; the order of the chunks reflects it.

### 3.5 Errors

A problem response is a `*Problem` (`Type`, `Title`, `Status`, `Detail`, the extension members), as in `internal/client`. `errors.Is` works against sentinels per problem slug that clients decide on. The slugs the server sends today: `not-found` (`ErrNotFound`), `revision-conflict` (`ErrConflict`, a stale `expectedRevision`), `binding-busy` and `invalid-transition` and `resource-deprecated` (`ErrState`), `validation-failed`, `immutable-field` and `jurisdiction-unresolvable` (`ErrInvalid`), `forbidden` and `four-eyes-violation` (`ErrForbidden`), `unauthenticated` (`ErrUnauthenticated`), `unavailable` and `rate-limited` (`ErrUnavailable`), `maintenance` (`ErrMaintenance`). A test (AC-5) extracts the slugs from `internal/server` and fails on one with no mapping, so a new server slug is a decision, not a surprise. A `503` or `429` carries `RetryAfter`. A body that is not a problem is reported by status only: its text never goes into an error. Calls are not retried by the client, except `Wait` and idempotent `GET`s with a bounded back-off (`MaxRetries`, default 2).

### 3.6 What the package does not do

No cache, no global state, no goroutines of its own (a wait runs in the caller's goroutine), no file reads, no output. The one environment it honours is the standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`), through `net/http`, so that a program on a corporate network reaches a `ligo` elsewhere (decided 2026-11-14 on the user's question); a proxy only tunnels, so T-A1 holds: the server is still verified end to end.

### 3.7 The CLI

`internal/client` keeps what is the CLI's own (`Options`, the password prompt, the table/JSON/YAML printing) and calls `pkg/adminclient`. Its tests must pass unchanged in behaviour. Per AGENTS rule 8, no compatibility layer is kept.

## 4. Threat model

| ID | Threat | Mitigation |
|---|---|---|
| T-A1 | A wrong server answers as `ligo`, and receives the caller's LDAP password or an authorised request. | `https` only; the server is verified by `RootCAs` or by `ServerID` against the SPIFFE bundle; there is no option to skip verification; `HTTPClient`'s own TLS settings are replaced. Redirects are never followed (a `3xx` is an error), so credentials cannot be sent elsewhere. |
| T-A2 | The password leaks through a log, an error, `%v` or a trace. | The password sits in an unexported field of a type that prints as `[redacted]` in `String`, `GoString` and `LogValue`; error values carry the status and the problem's `type` and `detail`, never request headers or bodies; the package logs method, path and status only. |
| T-A3 | A hostile or compromised server exhausts the caller's memory or time. | Response bodies are read through a limit (8 MiB); every call has the caller's context; a page size cap; `Wait` is bounded by its context and a maximum interval. |
| T-A4 | A third party's program uses the client to approve its own request, bypassing maker-checker. | The package offers no approve, decline, ratify, revert or break-glass method for use by default: they live in a separate, clearly named file and are documented as for human tools only; the server still enforces who may decide and a distinct approver. The MCP server does not import them (its spec says so, and a test lists the methods it calls). |
| T-A5 | A stale read overwrites someone's change. | `expectedRevision` required on updates; a stale revision is `ErrConflict`; no silent re-read and retry. |
| T-A6 | A retry duplicates a change request. | Mutations are never retried by the client. |
| T-A7 | The generated code drifts from the contract, or a bad generator update changes behaviour. | The generated code is checked in and diffed in CI; the generator is pinned by version and hash; the exported API does not expose generated names. |
| T-A8 | A secret reaches the client through a response. | The admin API returns none (backlog 11); a test walks the OpenAPI schemas for fields named `password`, `secret`, `token` or `credential` and fails on an unlisted one. |

## 5. Tests first

Unit tests over `httptest` TLS servers, and the existing contract test (`internal/server/adminhttp`) as the oracle for the routes:

- **AC-1** `New` refuses a `ServerURL` that is not `https`, no verification source, both or neither authentication, and a missing password with `BasicAuth`.
- **AC-2** A server with another SPIFFE ID, or a certificate outside `RootCAs`, is refused; a redirect is refused and the `Authorization` header is not sent to the target.
- **AC-3** Every operation of the YAML has a method (a test parses the YAML and the package's exported methods, and lists the differences), and the method uses the verb and path of the YAML.
- **AC-13** Instances: each of the three kinds has list, get, audit, create, update and delete (AC-3 covers the names and paths); a reader's `GetPlatform` has no `Definition` and says so, a decider's has it; `CreateSecretStore` returns the change request and never claims the store exists; `UpdateIdentityProvider` without `expectedRevision` fails before any call.
- **AC-4** Pagination: the iterator follows `nextPageToken` to the end, stops on error, and stops when the caller stops.
- **AC-5** Problem mapping: each slug that has a sentinel maps to it; an unknown slug is a `*Problem`; a non-problem body is a status-only error that holds none of the body's text.
- **AC-6** `Update*` without `expectedRevision` fails before any request; a stale revision returns `ErrConflict` and no second call is made.
- **AC-7** `WaitChangeRequest` returns at each terminal state, honours `Retry-After`, backs off, and returns the context's error when it ends.
- **AC-8** The password never appears in `fmt` output, `slog` output or an error, with every verb.
- **AC-9** Bodies over 8 MiB are cut and reported.
- **AC-10** The CLI's tests pass over the new package; `ligo ... list` output is unchanged.
- **AC-11** `make generate` leaves no diff.
- **AC-12** The secret-field walk of T-A8.
- **Fuzz:** the problem decoder and the pagination token handling. **Benchmark:** a 10 000-item list through the iterator.
- **Lab:** the client against a real `ligo` over SVID and over LDAP Basic (`lab.sh serve test`): create a source and a target, bind, wait for the request, read the binding; `ErrConflict` on a stale revision; a `ligo` restart during a wait.

## 6. Documentation

A package comment and runnable `Example`s; a new **Part 3, "Automating ligo"**, in the Developer's Guide, with the chapter "Calling the admin API from Go" (Part 1 is for the developers of workloads and Part 2 for the developers of plugins; the developers of tools, the provider and the MCP server included, are a third audience; the provider spec may add chapters to it); the README lists `pkg/adminclient`; the Architecture and Design Guide gains the client in its component view and the threats of §4; `docs/` tests keep passing.

## 7. Chunks

Each chunk ends with `go test ./...`, `make lint`, `make vuln` and `make secrets`, and is committed only on the user's word.

| Chunk | Content |
|---|---|
| 0 | This spec, approved; the backlog rows. |
| 1 | The contract typed (§3.4b: done for change requests; to do for the instances, sources, targets, bindings and the rest, each with its test), then the generator set-up, `make generate`, the drift check (AC-3, AC-11, AC-12). |
| 2 | `Config`, `New`, authentication, server verification, errors, bodies (AC-1, AC-2, AC-5, AC-8, AC-9). Written 2026-11-14: `New(Config)` takes no context (it makes no call); `Config` has `Bundles` for the SPIFFE ID check with LDAP credentials; a `Secret` type redacts the password, and the client holds it in a closure so that a copy of a `Client` prints none. |
| 3 | The operations, pagination, `expectedRevision` (AC-3, AC-4, AC-6), in two steps: the reads, instance reads included (what the provider's data sources need), then the writes, instance filing included (its resources). |
| 4 | `WaitChangeRequest`, retries, the fuzz targets and the benchmark (AC-7). |
| 5 | The CLI moved onto the package (AC-10). |
| 6 | The lab, the documentation (§6). |

## 8. Decisions (settled in 0.3, for approval with the rest)

1. **One module.** `pkg/adminclient` follows `ligo`'s releases and is `v0` until `ligo` 1.0.0 (AGENTS rule 8). Third parties import `github.com/dihedron/ligo`, which brings the whole module's dependencies into their `go.sum`. If that proves too heavy for the provider, a split into a module of its own is a later, mechanical step.
2. **No human decisions in the package.** `approve`, `decline`, `ratify`, `revert` and `breakGlass` are not methods of `pkg/adminclient` (T-A4). The CLI keeps a small private call for them in `internal/client`. A tool that needs them says so in its own spec, and the package gains them then, in a separate file.
3. **The generator (settled 2026-11-14: the user chose it over hand-written types).** `oapi-codegen` v2.8.2, pinned by `go.mod` and `go.sum` as a `tool`, run by `make generate` into `pkg/adminclient/internal/gen/gen.go` and checked by `make generate-check` in CI; the document names every nested object and the network flow once, so the output has no anonymous structs. Its first output (21,000 lines, models and client) compiles and passes `go vet`. Originally: after a check that its output for the typed document compiles, passes `go vet` and is hidden behind the exported layer (§3.1). If the output is not acceptable as it is, the fallback is hand-written types for the typed schemas only, with the contract tests of §3.4b as the guard; that choice comes back to the user at the end of chunk 1, with the evidence.
4. **Shared helpers are copied,** not extracted, until a fourth user needs them (§0).

