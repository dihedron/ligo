# The Java client SDK

- **Version:** 0.1 (2026-11-20), approved by the user in plan mode
- **Backlog:** item 7 (Java), item 22 (Maven Central waits, with PyPI and the Terraform registries)
- **Branch:** `feature/java-sdk`
- **Depends on:** `.specs/ligo-client-sdk.md` (the Go SDK; everything not said here is the same), `.specs/ligo-client-sdk-python.md` (structure, golden documents, flow checks), `.specs/ligo-network-checks.md` §3 and §9

## 1. Why

A Java workload does by hand the steps the Go SDK does (`.specs/ligo-client-sdk.md` §1): fetch its SVID, call the workload API over mTLS accepting only ligo's SPIFFE ID, read the binding, fetch a JWT-SVID, log in to the store, read the credential, do it again before the lease ends. The Java SDK does them, with the idioms of the language: blocking calls, `CompletableFuture` twins, a cancellable watch.

## 2. Decisions (the user, 2026-11-20)

| Question | Decision |
|---|---|
| Where | `sdk/java/` in the ligo repository: one version, one CI, one release. |
| Transport | REST (`java.net.http.HttpClient`) and gRPC (`grpc-java`), selectable, both verifying ligo's SPIFFE ID. |
| Async | Every remote call has an `...Async` twin returning `CompletableFuture`; `watch` has a blocking and a listener form. |
| Java | 17 or later; CI runs 17 and 21. |
| SPIFFE | `java-spiffe` (`io.github.spiffe`), pinned to an exact version: v0.8.17 (2026-04-20) is maintained (commits in November 2026, 5 open issues), supports X.509 and JWT sources over the Workload API and a `TrustManager` that accepts only given SPIFFE IDs. |
| Build | Maven, wrapper checked in. Coordinates `io.github.dihedron.ligo:ligo-client`, package `io.github.dihedron.ligo.client`. |
| Publishing | Jar, sources jar and javadoc jar attached to the GitHub release and covered by the signed `checksums.txt`. Maven Central waits, together with PyPI and the Terraform and OpenTofu registries (backlog item 22). |
| License | MIT, as the Go and Python SDKs. |
| Flow testing | Built into the client (`checkFlows`), as in Go and Python. |

Why gRPC is possible here and not in Python: `grpc-java` takes a Netty `SslContext` over a `TrustManager`, and `java-spiffe`'s `SpiffeTrustManager` checks the server's SPIFFE ID (a URI SAN, no DNS name) against an allowed ID, so no hook is missing.

## 3. The package

```java
try (LigoClient c = LigoClient.builder()
        .address("ligo1.example.com:8443")
        .serverId("spiffe://example.com/ns/sys/sa/ligo")
        .allowedStores(List.of("https://vault.example.com"))
        .build()) {
    for (Binding b : c.bindings(Filter.target("orders-db"))) {
        Credential cred = c.credential(b);
    }
    c.credentialAsync(b).thenAccept(cr -> ...);
    try (Watch w = c.watch(Filter.target("orders-db"), WatchOptions.credentials())) {
        for (Event ev : w) { ... }
    }
    FlowResults results = c.checkFlows("orders-db");
}
```

### 3.1 The client

`LigoClient.builder()` with `address` (`host:port`, TLS always), `serverId` (the only SPIFFE ID accepted; required), `x509Source` and `jwtSource` (default: `java-spiffe`'s `DefaultX509Source` and `DefaultJwtSource` on `SPIFFE_ENDPOINT_SOCKET`), `storeRoots` (default: the JDK's), `allowedStores`, `pollInterval` (30 s), `transport` (`REST` default, or `GRPC`), `executor` (default: a daemon thread pool the client owns and shuts down in `close()`), `logger` (`System.Logger`). `build()` refuses what the Go `New` refuses. The client is thread-safe.

### 3.2 Operations

| Method | Go | Notes |
|---|---|---|
| `bindings(Filter)` / `bindingsAsync` | `Bindings` | ETag kept per filter; a 304 returns the remembered list; an empty list is not an error. |
| `flows(target)` / `flowsAsync` | `Flows` | Data only. |
| `credential(Binding)` / `credentialAsync` | `Credential` | `vault-static`, `vault-dynamic`; JWT-SVID for `auth.config.audience`; login at `auth/<authMount>/login`; read of `secretPath` (KV v2) or `credsPath`; `X-Vault-Namespace` when set. |
| `invalidate(Binding)` | `Invalidate` | Drops the remembered store token. |
| `connect(address, serverId)` | `TLSConfig` | An mTLS `SSLSocket` with the workload's SVID, TLS 1.3, to a server that presents `serverId` only (§3.4). |
| `watch(Filter, WatchOptions)` | `Watch` | A `Watch`: `AutoCloseable`, `Iterable<Event>` (blocking `next`), ends on `close()`. `watch(Filter, WatchOptions, Consumer<Event>)` returns a `Subscription` (`cancel()`) and delivers on the executor, in order. Kinds `ADDED`, `CHANGED`, `REMOVED`, `CREDENTIAL_ROTATED`; rotation at two thirds of the lease; state kept through failed polls; backoff and `Retry-After`. |
| `checkFlows(target, FlowOptions)` / `checkFlowData(flows, FlowOptions)` (+ `Async`) | `CheckFlows`, `CheckFlowData` | §5. |
| `close()` | `Close` | Cancels watches, drops the store tokens, closes the sources and the executor it created, the gRPC channel. |

`Binding` (with `description` and `annotations`, an unmodifiable copy), `Auth`, `Credential`, `Event`, `Flow`, `BindingFlows` are records with the Go fields in camel case; `Binding.endpoint()` returns `spec["endpoint"]`. None is `Serializable`. `Credential.toString` hides the password, the token and the JWT; `equals` compares the secret fields in constant time.

### 3.3 Errors

`LigoException` (unchecked) is the base. `Unauthorized`, `Unavailable` (with `retryAfter`, a `Duration` or `null`), `NoCredentialException`, `UnsupportedStrategy`, `StoreNotAllowed`, `StoreError`, `TooManyFlows` carry the meaning of the Go sentinels. Async calls complete exceptionally with the same types (never wrapped in more than the `CompletionException` the JDK adds). A message holds a status, never a secret.

### 3.4 TLS

- **The context.** The SVID and the bundle come from `java-spiffe`'s `X509Source` in memory: no key file touches the disk (T-J1). The `SSLContext` is built with a key manager over the source and `SpiffeTrustManager` set to accept only `serverId`; protocols TLS 1.3 only.
- **The ID check.** Done in the trust manager during the handshake, before the first byte of the request. The JDK hostname check is off because an SVID has no DNS name; there is no option to turn the ID check or the verification off.
- **gRPC.** `NettyChannelBuilder` with a `GrpcSslContexts` client context over the same key and trust managers, `passthrough:///address`, `maxInboundMessageSize` 8 MiB. A refused ID is reported as `Unauthorized`.
- **Rotation.** Both managers read the source on every handshake, so a rotated SVID or bundle applies to the next connection.
- **The store.** Its own `HttpClient` and `SSLContext` from `storeRoots`, `https` only, pinned by `allowedStores`, redirects never followed, bodies limited to 8 MiB, a 15 s timeout.

## 4. Threat model

The Go rows T-C1 to T-C8 and the Python rows T-P2, T-P3, T-P5 and T-P6 apply. New or changed:

| ID | Threat | Mitigation |
|---|---|---|
| T-J1 | The private key reaches the disk. | It does not: the SSL context is built from in-memory keys. Tested: no file is created during a connection. |
| T-J2 | A server that is not ligo receives the request, on REST or gRPC. | The ID is checked in the handshake; tested with a server of another ID on both transports. |
| T-J3 | A secret in `toString`, an exception message, a log, a heap dump of serialized state. | `Credential` redacts everywhere; no `Serializable`; exceptions carry statuses; tested over `toString`, `String.valueOf`, the logger and exceptions. |
| T-J4 | Supply chain: `java-spiffe`, `grpc-java`, `netty`, `protobuf`, `jackson`. | Exact versions in `pom.xml`, `maven-enforcer` dependency convergence, a dependency audit and dependency review in CI, the jar built in CI from the tag, covered by the signed checksums. |
| T-J5 | Unsafe deserialization. | The SDK reads JSON with Jackson with default typing off and unknown fields ignored, protobuf messages for gRPC, and never Java serialization. |
| T-J6 | Threads or sockets leak after `close()` or `cancel()`. | `close()` cancels every watch and check, shuts down the executor it owns and the channel; tested for leftover threads. |
| T-J7 | A caller's executor is starved or blocked by a slow store. | Timeouts on every call; the watch runs on its own thread, not on the caller's executor, when none is given. |
| T-J8 | `checkFlows` is used to scan. | As T-P6: destinations vetted against `allowed_endpoints` by the server, link-local and metadata ranges denied, no range expanded, 1,024 checks at most. |

## 5. Flow testing

`checkFlows` and `checkFlowData`: the semantics of Go and Python (`.specs/ligo-network-checks.md` §3 and §9, `.specs/ligo-client-sdk-python.md` §5): one `FlowResult` per flow and port with `binding`, `target`, `flow`, `destination`, `port`, `protocol` (`tcp`, `tls`, `postgresql`, `spire`, `udp`), `status` (`REACHABLE`, `UNREACHABLE`, `SKIPPED`), `reason`, `error`, `latency`, `attempts`. The checks in the JDK alone: `Socket` connect; `SSLSocket` handshake with the name verified; the PostgreSQL `SSLRequest` then TLS; the SPIFFE check against the bundle (any ID of the trust domain, or `spiffeId`); a datagram on a connected `DatagramChannel` for UDP. Defaults: 5 s a try, 2 tries, 8 at a time, 1,024 checks, link-local and metadata ranges denied (`deniedNetworks`), the name resolved once and the vetted address connected, `handshake` callback to choose the check. No ICMP.

## 6. Tests first

JUnit 5 and AssertJ, with an in-memory CA and in-process TLS servers (`SSLServerSocket`, `HttpsServer`, `grpc` `NettyServerBuilder`). Numbers follow the Go CS-n and the Python PY-n; each runs on both transports where it applies.

- **JV-1** the builder refuses what the Go `New` refuses. **JV-2** `bindings` decodes `spec` and `auth`; an empty list is not an error. **JV-3** the second call sends the ETag and returns the remembered list. **JV-4** a server with another SPIFFE ID gets no request (`Unauthorized`); 503 and 429 are `Unavailable` with `retryAfter`.
- **JV-6, JV-7** `credential` on `vault-static` and `vault-dynamic`. **JV-8** store-token reuse, one retry on 403, `invalidate`. **JV-9** `NoCredentialException`, `UnsupportedStrategy`, `StoreNotAllowed`, an `http` store, a store certificate outside `storeRoots`, a binding with no audience. **JV-10** no log line, exception, `toString` or serialization holds the password, the token or the JWT. **JV-13** a body over 8 MiB is refused. **JV-15** the namespace goes on the login and the read.
- **JV-11, JV-12** `watch`: events in order, rotation at two thirds of a lease, state kept through failed polls, backoff, `Retry-After`, `close()` and `cancel()`.
- **JV-A1 to JV-A4** the async twins: same results, exceptional completion with the same types, cancelling a future, `close()` with calls in flight.
- **JV-T1** no file is created while connecting. **JV-T2** no thread survives `close()`.
- **JV-F1 to JV-F9** flow testing as the Go FC-n and Python PY-F.
- **JV-G** the golden documents in `api/testdata/workload/` decoded by Go, Python and Java to equal values.
- Property tests (`jqwik`) on a bindings document and a store response. A JMH benchmark of `bindings` answered 304.

Lab (the release-run, OpenBao and Vault; written first, run overnight):

- **JV-L1** a Java echo client (`test/lab/echo/client-java`) as `echo-bound` on ligo1 in `lab.sh echo smoke`, with the real SPIRE agent, on REST and on gRPC.
- **JV-L2** `lab.sh serve test-java`: a `vault-dynamic` PostgreSQL binding as `TestServeClientSDK`: `added`, a credential that connects, rotation, then `removed` and a refused credential; on both transports.
- **JV-L3** the flow scenario of Go's FC-L1 to FC-L5 in Java, with the same block of the database host.

## 7. CI, build and release

- `ci.yml` gets a `java` job on 17 and 21: `mvn verify` (tests, `maven-enforcer`, SpotBugs), javadoc, the dependency audit; CodeQL covers `java-kotlin`.
- `make java-test`, `java-lint`, `java-build`. `make lint` stays Go.
- The version is the ligo tag, passed to Maven (`-Drevision`); `0.0.0-SNAPSHOT` without a tag.
- `release.yml` builds the jar, the sources jar and the javadoc jar from the tag (JDK 17) and attaches them with the checksums; `.goreleaser.yaml` adds them to `extra_files`.

## 8. Documentation

A Developer's Guide chapter "The Java SDK" (client, bindings, credential and JDBC, watch, async, gRPC, revocation, flow testing, errors, security); `07-other-languages.md` keeps JavaScript/TypeScript only; the Architecture and Design Guide gets the SDK in the component view and the T-J rows; the README; `sdk/java/README.md`.

## 9. Chunks

| Chunk | Content |
|---|---|
| 0 | This spec, the backlog (item 22 with Maven Central, item 7), the provider backlog note. |
| 1 | The Maven project, builder, the mTLS context and the ID check, `bindings`, `flows` on REST (JV-1 to JV-4, JV-13, JV-T1). |
| 2 | `credential`, the store, errors, property tests (JV-6 to JV-10, JV-15). |
| 3 | The gRPC transport and the async twins (JV-A, and JV-2 to JV-4 on gRPC). |
| 4 | `watch`, flow testing, golden documents, the benchmark (JV-11, JV-12, JV-F, JV-G, JV-T2). |
| 5 | CI, `make` targets, the release wiring. |
| 6 | The guide, the READMEs, the threat rows, the lab (written, not run; overnight). |
| 7 | The PR; merge on the user's word. |

## 10. Out of scope

Maven Central (backlog item 22), Kotlin or Scala wrappers, reactive streams, ICMP in flow testing, connection pooling beyond what `HttpClient` and the gRPC channel do, signing or attesting the jar.
