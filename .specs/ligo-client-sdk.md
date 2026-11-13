# The Go client SDK

- **Version:** 1.0 (2026-11-13), approved
- **Backlog:** item 7 (Go first; Java, Python and JavaScript/TypeScript stay in the backlog)
- **Branch:** `feature/client-sdk`, from main at v0.4.0 (`61f9af4`)
- **Main spec:** becomes 4.1.1 (the Vault plugin's client auth gains `audience`, §4)
- **Guides:** `.specs/ligo-client-sdk-guides.md`

## 1. Why

A workload that wants its bindings does every step by hand today:

1. it fetches its X.509-SVID from its SPIRE agent;
2. it calls `ligo`'s workload API over mTLS, accepting only `ligo`'s SPIFFE ID;
3. it reads the `spec` and the `auth` of each binding;
4. it fetches a JWT-SVID with the secret store's audience;
5. it logs in to the store and reads its credential;
6. it connects to the target, and does steps 4 to 6 again when the credential rotates.

The lab's `echo-client` (`test/lab/echo/client`, `.specs/ligo-echo-target.md`) does all of this in about 240 lines, but it is lab code: it is not hardened, it takes the store's audience from a flag, and it does not follow rotation. The SDK makes these steps a supported Go package, `pkg/client`.

## 2. Decisions (the user, 2026-11-13)

| Question | Decision |
|---|---|
| Where it lives | `pkg/client`, in `github.com/dihedron/ligo`. One version, one CI, one release. |
| What it covers | Bindings (with ETag), credentials for `vault-static` and `vault-dynamic`, a watch for changes and rotation, and flows as data. The SDK returns the endpoint, the credential and a TLS configuration; the application opens the connection with its own driver. |
| Transport | REST and gRPC, chosen by an option. Both return the same data. |
| Documentation | A new release PDF, the **Developer's Guide**: part 1 on developing an application with the client SDK (Go now; Java, Python and JavaScript/TypeScript later), part 2 ("Advanced development") on writing plugins of the three types with `pkg/pluginsdk`. |

## 3. The package

### 3.1 Creating a client

```go
c, err := client.New(ctx, client.Config{
    Address:   "ligo1.example.com:8443",                    // ligo's workload API, host:port
    ServerID:  "spiffe://example.com/ns/sys/sa/ligo",       // the only SPIFFE ID accepted for ligo
    Transport: client.REST,                                 // or client.GRPC; REST when empty
})
if err != nil { … }
defer c.Close()
```

`Config` fields:

| Field | Required | Meaning |
|---|---|---|
| `Address` | yes | `host:port` of the workload API. No scheme: the SDK always uses TLS. |
| `ServerID` | yes | `ligo`'s SPIFFE ID. Any other peer is refused. |
| `Transport` | no | `client.REST` (default) or `client.GRPC`. |
| `X509Source` | no | An `x509svid.Source` and `x509bundle.Source`. Default: a `workloadapi.X509Source` on `SPIFFE_ENDPOINT_SOCKET`, owned and closed by the client. |
| `JWTSource` | no | Returns a JWT-SVID for an audience. Default: the same Workload API socket, through one client kept open. |
| `StoreRoots` | no | The CA pool for the secret store's certificate. Default: the system's roots. |
| `AllowedStores` | no | Store addresses the SDK may log in to (`https://host:port`; port 443 when omitted). Empty means any address a binding names (§7, T-C2). |
| `PollInterval` | no | The watch's interval. Default 30 s, never under 5 s. |
| `Logger` | no | A `*slog.Logger`. Default: `slog.Default()`. |

`New` validates the configuration and opens the SVID source. It does not call `ligo`: the first call does.

### 3.2 Bindings

```go
bs, err := c.Bindings(ctx, client.Filter{Target: "orders-db"})
```

- `Filter` has `Target` and `PlatformType`, both optional, as the API has.
- The answer is a `[]Binding`, possibly empty. An empty answer is not an error: the caller has no binding.
- The client remembers the last ETag and answer per filter and sends it back (`If-None-Match`, or `known_etag` on gRPC). A "not modified" answer returns the remembered list.

```go
type Binding struct {
    ID, Name, Source, Target string
    AccessLevel              string
    PlatformType, Platform   string
    Revision                 int64
    UpdatedAt                time.Time
    Spec                     map[string]any // differs per platform type (endpoint, database, user, serverId, …)
    Auth                     Auth
}

type Auth struct {
    Strategy      string            // secretStorageStrategy: "vault-static", "vault-dynamic", or empty
    StoreType     string
    StoreInstance string
    Config        map[string]string // what the store plugin finalized: address, audience, namespace, authMount, role, secretPath or credsPath
}
```

`Binding.Endpoint()` returns `Spec["endpoint"]` when it is a string, as a convenience; nothing else in `Spec` is interpreted.

### 3.3 Credentials

```go
cred, err := c.Credential(ctx, b)
```

```go
type Credential struct {
    Username string
    Password string
    Expires  time.Time // zero when the store gives no lease (vault-static)
}
```

- **`vault-static` and `vault-dynamic`** (store types `vault`, also OpenBao):
  1. fetch a JWT-SVID for `auth.config.audience`, for the same SPIFFE ID as the X.509-SVID in use;
  2. `POST <address>/v1/auth/<authMount>/login` with `role` and the JWT;
  3. read `secretPath` (KV version 2: `data.data.username`, `data.data.password`) or `credsPath` (database engine: `data.username`, `data.password`, `lease_duration`).
- When `auth.config.namespace` is set (Vault Enterprise, HCP Vault, OpenBao 2.3 and later), every request to the store carries it in `X-Vault-Namespace`.
- The store's token is kept in memory per (address, namespace, authMount, role) until 80 % of its TTL, then a new login is made. A `403` on a read with a remembered token causes one new login and one retry.
- `Credential` is not cached by `Credential()`: each call reads the store. For `vault-dynamic` each read creates a new database user, so an application calls it once and then follows the watch (§3.5).
- `c.Invalidate(b)` drops the remembered store token for the binding. An application calls it when the target refuses the credential.
- A binding with an empty `Strategy` (an SVID-only mode) returns `ErrNoCredential`. Another strategy returns `ErrUnsupportedStrategy`.
- `Credential` implements `fmt.Stringer`, `fmt.GoStringer` and `slog.LogValuer`, and all hide the password.
- The store's address must be `https://host[:port]`, with no path. The SDK follows no redirect from a store: a redirect would carry the JWT-SVID or the store's token to another host.

### 3.4 TLS configuration and flows

- `c.TLSConfig(serverID)` returns a `*tls.Config` for mTLS with the workload's SVID that accepts only `serverID`. It is for targets that speak SPIFFE mTLS (`Spec["serverId"]`).
- `c.Flows(ctx, filter)` returns `[]BindingFlows` (`Binding`, `Source`, `Target`, `Flows []Flow` with name, purpose, protocol, destination, ports, tls, serverName, description, declaredBy). It is data only: checking the flows is backlog item 12. Only `Filter.Target` applies.

### 3.5 Watching

```go
err := c.Watch(ctx, client.Filter{Target: "orders-db"}, func(ev client.Event) { … })
```

- `Watch` blocks until `ctx` ends and returns `ctx.Err()`. The handler runs on the watch's goroutine, one event at a time.
- The server has no stream, so `Watch` polls `Bindings` with the ETag every `PollInterval`, with up to 10 % jitter.
- Events:

  | `Event.Kind` | When | Fields |
  |---|---|---|
  | `Added` | A binding appears (also every binding on the first poll). | `Binding` |
  | `Changed` | The `Revision` of a known binding changed. | `Binding`, `Previous` |
  | `Removed` | A known binding is no longer returned (revoked, expired). | `Previous` |
  | `CredentialRotated` | A new credential was read for the binding. | `Binding`, `Credential` |

- **Credentials in the watch.** When `WatchCredentials` is set in the filter:
  - after `Added` and after `Changed`, the watch reads the credential and emits `CredentialRotated`;
  - for a credential with an `Expires`, it reads again at two thirds of the lease and emits `CredentialRotated`;
  - a failed read is logged at WARN and tried again at the next poll. It emits nothing;
  - a binding with no secret store (`ErrNoCredential`) is skipped silently.
- **Failures.** A failed poll keeps the last good state and emits nothing. The watch waits `PollInterval` after the first failure, then doubles the wait at each further failure, up to 5 minutes, and returns to `PollInterval` after a success. When `ligo` says when to come back, the watch waits at least that long (up to one hour): `Retry-After` on REST, a `google.rpc.RetryInfo` detail on gRPC.
- **Order.** At one poll, `Added` and `Changed` come in the order of the answer, then `Removed` by binding name.

### 3.6 Errors

Every error is wrapped with `%w`. Sentinels, for `errors.Is`:

| Error | Meaning |
|---|---|
| `ErrUnauthorized` | `ligo` refused the caller (TLS alert, `401`, `403`, gRPC `Unauthenticated` or `PermissionDenied`). |
| `ErrUnavailable` | `ligo` cannot resolve now (`503`, gRPC `Unavailable`), limits the caller's rate (`429`, gRPC `ResourceExhausted`), or cannot be reached. Retry later. |
| `ErrNoCredential` | The binding has no secret store. |
| `ErrUnsupportedStrategy` | The SDK does not know the binding's strategy. |
| `ErrStoreNotAllowed` | The binding names a store address that is not `https`, or is outside `AllowedStores`. |
| `ErrStore` | The store refused the login or the read; the message has the HTTP status, never the body. |

### 3.7 Transports

- **REST:** `net/http`, `GET /v1/bindings` and `GET /v1/flows`, `If-None-Match`.
- **gRPC:** the generated client of `api/gen/workload/v1alpha1`; `Struct` fields are converted to the same Go values as the REST JSON.
- Both use `tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID))`, TLS 1.3 only, a 15 s timeout per call, and bodies limited to 8 MiB.
- For the same server state, the two transports return equal `[]Binding` and `[]BindingFlows`. A test proves it.

## 4. Changes on the server

The binding's `auth.config` carries `address`, `policy`, `authMount`, `role` and `secretPath` or `credsPath`, but not the audience of the JWT-SVID the store expects, nor the store's namespace. A workload cannot log in without them.

- The Vault plugin adds `"audience"` to the finalized client auth, with the instance's `workload_jwt_audience`, and to its `client_output_schema_json`.
- The Vault plugin adds `"namespace"` when the instance has one; the field is absent otherwise.
- The workload API's gRPC errors carry a `google.rpc.RetryInfo` detail where REST sends `Retry-After`: 5 s on `Unavailable` (the cache is stale), 1 s on `ResourceExhausted` (the caller's rate limit). The two transports then give a client the same hint.
- No compatibility code: bindings applied before the change gain the field at their next apply. The SDK reports a binding without it as `ErrStore` ("the binding names no audience").
- Main spec 4.1.1, with a changelog row.

## 5. Logging

`log/slog`, with the keys `binding`, `target`, `transport` and `store` (the address). Never a token, a JWT-SVID, a password or a store's response body.

## 6. Dependencies

`github.com/spiffe/go-spiffe/v2` and, for the gRPC transport, `google.golang.org/grpc` and the generated package. All are in `go.mod` already. `pkg/client` imports nothing from `internal/`.

## 7. Threat model

| ID | Threat | Mitigation |
|---|---|---|
| T-C1 | A wrong server answers as `ligo`, or as the store. | `ligo` is accepted only with `ServerID`, over mTLS, against the SPIFFE bundle. The store is accepted only over TLS against `StoreRoots`. The SDK has no option to skip verification and refuses a store address that is not `https`. |
| T-C2 | A compromised `ligo`, or a tampered answer, names a store address the attacker controls, to collect the workload's JWT-SVID. | The JWT-SVID carries the audience of the binding, so it is of use only against a store that trusts that audience. `AllowedStores` pins the addresses; the Developer's Guide recommends it. No redirect from a store is followed. |
| T-C3 | Secrets leak through logs, errors or `%v`. | `Credential` hides its password in `String` and `LogValue`. Errors carry statuses, never bodies. Tokens and JWTs are never logged. |
| T-C4 | Secrets stay in memory or on disk longer than needed. | Nothing is written to disk. A store token is dropped at 80 % of its TTL and at `Close`. Credentials are not cached by the SDK. |
| T-C5 | A credential read during a rotation is stale. | The watch re-reads after a `Changed` event and before a lease ends; `Invalidate` forces a new login. |
| T-C6 | Many workloads polling overload `ligo`. | A 5 s floor on the interval, jitter, the ETag (a `304` has no body), backoff after failures, `Retry-After` and `RetryInfo` honoured. |
| T-C7 | A hostile answer exhausts memory. | Bodies are read through an 8 MiB limit, on `ligo` and on the store. |
| T-C8 | A revoked binding keeps being used. | The watch emits `Removed` within one poll interval. The SDK cannot close the application's connections: the guide says what the application must do. The store's policy is removed by `ligo` at revocation, so new credential reads fail. |

## 8. Tests first

Unit tests, with in-memory SVIDs and `httptest` TLS servers (the pattern of `test/lab/echo/client/client_test.go`):

- **CS-1** `New` refuses a missing `Address` or `ServerID`, a bad SPIFFE ID, an unknown transport, an `AllowedStores` entry that is not `https://host:port`, and a `PollInterval` under 5 s.
- **CS-2** `Bindings` returns the server's items, with `Spec` and `Auth` decoded; an empty list is not an error.
- **CS-3** A second `Bindings` sends the ETag; on "not modified" it returns the remembered list.
- **CS-4** A server with another SPIFFE ID is refused (`ErrUnauthorized`); a `503` is `ErrUnavailable`.
- **CS-5** CS-2 to CS-4 and `Flows` pass on both transports, and the two transports return equal values from the real `workloadhttp` handler.
- **CS-6** `Credential` on `vault-static`: login with the JWT for `auth.config.audience`, read of `secretPath`; `Expires` is zero.
- **CS-7** `Credential` on `vault-dynamic`: read of `credsPath`; `Expires` follows `lease_duration`.
- **CS-8** The store token is reused until 80 % of its TTL; a `403` with a remembered token causes one login and one retry; `Invalidate` drops it.
- **CS-9** `ErrNoCredential`, `ErrUnsupportedStrategy`, `ErrStoreNotAllowed`, a store over `http`, a store with a certificate outside `StoreRoots`, a binding with no audience.
- **CS-10** No log line and no error text contains the password, the token or the JWT; `fmt.Sprint(cred)` hides the password.
- **CS-11** `Watch` emits `Added`, `Changed`, `Removed` in order for a scripted server; with `WatchCredentials` it emits `CredentialRotated` after each, and again at two thirds of a lease.
- **CS-12** `Watch` keeps its state through failed polls, backs off, honours `Retry-After`, and returns `ctx.Err()` when the context ends.
- **CS-13** Bodies over 8 MiB are refused.
- **CS-14** The Vault plugin's finalized client auth has `audience`, and `namespace` when the instance has one; its output schema allows both.
- **CS-15** A binding's namespace is sent on the login and on the read; a login in one namespace is not used in another.
- **CS-16** The server's gRPC errors carry `RetryInfo` (5 s stale, 1 s rate-limited), and the SDK's gRPC transport reads it as its REST transport reads `Retry-After`.

Fuzzing: one target for decoding a bindings document (REST body and gRPC `Struct`), one for the store's responses. Benchmark: `Bindings` answered "not modified".

Lab (in the release-run, on OpenBao and Vault):

- **CS-L1** `echo-client`, rebuilt on `pkg/client`, passes the echo suites with `--transport rest` and with `--transport grpc`.
- **CS-L2** A `vault-dynamic` PostgreSQL binding: a client built on the SDK reads its credential and runs a query; after its lease the watch delivers a new credential that also works.
- **CS-L3** A revoked binding: the watch reports `Removed`, and a new credential read fails.

## 9. Chunks

Each chunk ends with `go test ./...`, `make lint`, `make vuln` and `make secrets`, and is committed only on the user's word.

| Chunk | Content |
|---|---|
| 0 | This spec, the guides file, the backlog row. |
| 1 | The server change of §4 (CS-14), main spec 4.1.1. |
| 2 | `pkg/client`: `Config`, `New`, the REST transport, `Bindings`, `Flows`, `TLSConfig`, errors (CS-1 to CS-4, CS-13). |
| 3 | The gRPC transport and the tests over both (CS-5). |
| 4 | Credentials (CS-6 to CS-10), the fuzz targets. |
| 5 | `Watch` (CS-11, CS-12), the benchmark. |
| 6 | The lab (CS-L1 to CS-L3), the Developer's Guide and the other documents (§10), the release-run. |

## 10. Documentation

- **Developer's Guide** (`docs/developers-guide/`), a release PDF built by `make docs` and attached by the Documents workflow, as the other guides are:
  - **Part 1, "Developing an application":** what a binding gives a workload; the Go SDK step by step (client, bindings, credential, connection, watch, revocation); error handling; security advice (`AllowedStores`, what to do on `Removed`); a complete example. Sections for Java, Python and JavaScript/TypeScript say that those SDKs follow.
  - **Part 2, "Advanced development":** writing a plugin of each type (identity provider, secret store, platform) with `pkg/pluginsdk`: the protocol (version 2), `Describe` and the schemas, `ValidateInstance`, `ConfigureInstances`, the stages, errors, SVID selection, testing with `testdata/testplugin`, packaging and the SHA-256 pin. Text on writing plugins that is in the Setup Guide or the Architecture and Design Guide today moves here, and a pointer stays behind.
- The Architecture and Design Guide gains the SDK in its component view and the rows of §7.
- The README lists the SDK and the fifth guide.
- `pkg/client` has a package comment and a runnable `Example`.

## 11. Out of scope

- Ready connections per platform type (a `database/sql` connector, an LDAP bind).
- Network checks on the flows (backlog item 12).
- SDKs in Java, Python and JavaScript/TypeScript (backlog item 7, later).
- A streaming watch on the server.
- Secret stores other than Vault and OpenBao.
