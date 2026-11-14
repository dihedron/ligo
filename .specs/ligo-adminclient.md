# The Go admin API client

- **Version:** 0.2 (2026-11-14), draft: waits for approval; 0.2 reconciles 0.1 with the Go client SDK (§0) and the contract as it is (§3.4, §3.5)
- **Backlog:** item 8 (Terraform and OpenTofu provider) and item 11 (MCP server), which both need it
- **Branch:** this spec travels with the client SDK (`feature/client-sdk`); the code goes on `feature/adminclient`, cut from `main` once the client SDK is merged, because chunk 6 extends the Developer's Guide and the code reuses what `pkg/client` settled (§0)
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

In: `pkg/adminclient`, a Go package of this module, for every operation of `admin.v1alpha1.yaml`; the CLI moved onto it.
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
- **The contract has gaps the client needs closed first (chunk 1).** `admin.v1alpha1.yaml` does not enumerate a change request's `status`, so the terminal states of `WaitChangeRequest` would be a copy in Go; and since backlog item 10 its `resourceType` enums (`listChangeRequests`, the charter preview's `kind`) lack `PLATFORM`, `IDENTITY_PROVIDER` and `SECRET_STORE`, so a generated client would reject a request the server files. Chunk 1 fixes the YAML (with the contract test of `internal/server/adminhttp` as the oracle) before it generates anything.
- Updates take `expectedRevision`; a missing one is an error before any call.
- `WaitChangeRequest(ctx, id, WaitOptions)` polls until the request is in a terminal state (`APPLIED`, `REJECTED`, `WITHDRAWN`, `EXPIRED`, `FAILED`) or the context ends. Polling has a floor of 1 s, jitter, back-off after failures, and honours `Retry-After`. The terminal states and the optional wait for a binding to be `ACTIVE` come from the API's enums, not from a copy.
- `approvalReference` and `automationContext` (delegated approval, ADR-11) are fields of the mutation request, passed through unchanged. The client never approves, declines, ratifies or reverts anything by itself.

### 3.5 Errors

A problem response is a `*Problem` (`Type`, `Title`, `Status`, `Detail`, the extension members), as in `internal/client`. `errors.Is` works against sentinels per problem slug that clients decide on. The slugs the server sends today: `not-found` (`ErrNotFound`), `revision-conflict` (`ErrConflict`, a stale `expectedRevision`), `binding-busy` and `invalid-transition` and `resource-deprecated` (`ErrState`), `validation-failed`, `immutable-field` and `jurisdiction-unresolvable` (`ErrInvalid`), `forbidden` and `four-eyes-violation` (`ErrForbidden`), `unauthenticated` (`ErrUnauthenticated`), `unavailable` and `rate-limited` (`ErrUnavailable`), `maintenance` (`ErrMaintenance`). A test (AC-5) extracts the slugs from `internal/server` and fails on one with no mapping, so a new server slug is a decision, not a surprise. A `503` or `429` carries `RetryAfter`. A body that is not a problem is reported by status only: its text never goes into an error. Calls are not retried by the client, except `Wait` and idempotent `GET`s with a bounded back-off (`MaxRetries`, default 2).

### 3.6 What the package does not do

No cache, no global state, no goroutines of its own (a wait runs in the caller's goroutine), no file or environment reads, no output.

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
| 1 | The generator set-up, `make generate`, the drift check (AC-3, AC-11, AC-12). |
| 2 | `Config`, `New`, authentication, server verification, errors, bodies (AC-1, AC-2, AC-5, AC-8, AC-9). |
| 3 | The operations, pagination, `expectedRevision` (AC-3, AC-4, AC-6). |
| 4 | `WaitChangeRequest`, retries, the fuzz targets and the benchmark (AC-7). |
| 5 | The CLI moved onto the package (AC-10). |
| 6 | The lab, the documentation (§6). |

## 8. To decide

1. The module's own version: `pkg/adminclient` follows `ligo`'s releases, and is `v0` until `ligo` 1.0.0 (AGENTS rule 8). Third parties import `github.com/dihedron/ligo`, which brings the whole module's dependencies into their `go.sum`. If that proves too heavy for the provider, a split into a module of its own is a later, mechanical step.
2. Whether `approve`/`decline`/`ratify`/`revert`/`breakGlass` are in the package at all (T-A4). Leaving them out is safest; the CLI would then keep a small private call for them.
3. The `oapi-codegen` version and whether its strict-client output is accepted as it is.
4. Whether the few helpers shared with `pkg/client` (§0) move into one internal package. Recommendation: not yet; copy them, and extract when the provider or the MCP server needs a fourth.
