# The Java SDK

```java
import io.github.dihedron.ligo.client.LigoClient;
```

`ligo-client` for Java is the counterpart of the Go and Python SDKs of the previous chapters: the same operations, the same data and the same rules, in the idioms of Java. It needs Java 17 or later and depends on [java-spiffe](https://github.com/spiffe/java-spiffe), `jackson-databind` and `grpc-java`. It is MIT-licensed, unlike `ligo` itself. Its coordinates are `io.github.dihedron.ligo:ligo-client`, and the package is `io.github.dihedron.ligo.client`.

The jar, the sources jar, the javadoc jar and the `pom` are attached to each release of `ligo`, and covered by its signed checksums (the library is not on Maven Central yet). Take the version that matches your `ligo`. The `pom` lists the dependencies, so a build tool can resolve them:

```bash
mvn install:install-file -Dfile=ligo-client-X.Y.Z.jar -DpomFile=ligo-client-X.Y.Z.pom
```

and then depend on `io.github.dihedron.ligo:ligo-client:X.Y.Z`.

The SDK speaks REST (the default) or gRPC, with the same results. Every call that goes to the network has a blocking form and an `Async` twin that returns a `CompletableFuture`. The client is safe to use from several threads.

## Creating a client

```java
try (LigoClient client = LigoClient.builder()
        .address("ligo.example.com:8443")                         // the workload API: host:port, no scheme
        .serverId("spiffe://example.com/ns/sys/sa/ligo")          // the only SPIFFE ID accepted for ligo
        .allowedStores(List.of("https://vault.example.com:8200"))
        .build()) {
    ...
}
```

`build()` checks its arguments and throws `IllegalArgumentException`; it does not call `ligo`. The SVID comes from the SPIRE agent at `SPIFFE_ENDPOINT_SOCKET`, as for every SPIFFE program, when the client first needs it. `close()` stops the watches, forgets the store tokens and closes what the client opened.

| Builder method | Meaning |
| :-------------- | :----------------------------------------------------------------- |
| `address` | `host:port` of the workload API. Always TLS. |
| `serverId` | `ligo`'s SPIFFE ID. Any other peer is refused. |
| `x509Source` | Your own source of the SVID and bundles (a java-spiffe `X509Source`); default: the Workload API. The client never closes a source you give. |
| `jwtSource` | Your own source of JWT-SVIDs (a `JwtSvidSource`); default: the Workload API. |
| `storeRoots` | The CAs of the secret store's certificate: a PEM file or a list of certificates; default: the JDK's. |
| `allowedStores` | The store addresses (`https://host:port`) the client may log in to. See "Errors and security". |
| `pollInterval` | Time between two polls of `watch`; default 30 s, at least 5 s. |
| `transport` | `LigoClient.Transport.REST` (default) or `GRPC`. |
| `executor` | Runs the `Async` calls; default: a daemon thread pool the client owns and shuts down in `close()`. |
| `logger` | A `System.Logger`; default `io.github.dihedron.ligo.client`. |

## Bindings

```java
List<Binding> bindings = client.bindings(Filter.target("orders-db"));
if (bindings.isEmpty()) {
    throw new IllegalStateException("no binding to orders-db");
}
Binding b = bindings.get(0);
System.out.println(b.name() + " " + b.platformType() + " " + b.endpoint());
```

No binding is an empty list, not an error. `Filter.all()`, `Filter.target(t)` and `new Filter(target, platformType)` narrow the list. A `Binding` is a record with the fields of the second chapter in camel case, including `description` and `annotations` (an unmodifiable map: both are data, never run them). `spec` is a map, since it differs per platform type, and `endpoint()` returns `spec.get("endpoint")`, or an empty string.

The client remembers the last answer for each filter and sends its ETag the next time. When nothing has changed, `ligo` answers without a body and the client returns the remembered list, so a call is cheap.

`client.bindingsAsync(filter)` is the same call as a `CompletableFuture<List<Binding>>`. A failure completes the future exceptionally with the same exception type (inside the `CompletionException` that `join` adds), and cancelling the future interrupts the call.

## Credentials

```java
Credential cred = client.credential(b);
String[] hostPort = b.endpoint().split(":");
Connection conn = DriverManager.getConnection(
        "jdbc:postgresql://" + b.endpoint() + "/" + b.spec().get("database") + "?sslmode=verify-full",
        cred.username(), cred.password());
```

`credential` logs in to the secret store with a JWT-SVID and reads the credential of the binding. `cred.expires()` is an `Instant` at the end of the lease, or `null` when there is none.

- Every call reads the store. With `vault-dynamic` each read creates a new database user, so read once and keep the result; do not call it for every connection.
- `cred.toString()`, string concatenation, a log line or a stack trace never show the password. `Credential` is not `Serializable`, and its `equals` compares the password in constant time. Read `cred.password()` when you need it.
- A binding that needs no credential (the `svid` strategy) throws `NoCredentialException`. Connect with the SVID:

```java
try (SSLSocket socket = client.connect("orders.example.com:5433", "spiffe://example.com/ns/db/sa/orders",
        Duration.ofSeconds(15))) {
    ...
}
```

`connect` opens an mTLS connection with the workload's SVID, TLS 1.3 only, to a server that presents exactly the SPIFFE ID you name. The handshake is done and the ID is checked when it returns.

## Following rotation and revocation

`watch` polls `ligo` and reports each change as an `Event`. The returned `Watch` is an `Iterable<Event>` that blocks between events, on its own thread:

```java
try (Watch watch = client.watch(Filter.target("orders-db"), WatchOptions.withCredentials())) {
    for (Event ev : watch) {
        switch (ev.kind()) {
            case ADDED, CHANGED -> System.out.println("binding " + ev.binding().name() + " revision " + ev.binding().revision());
            case CREDENTIAL_ROTATED -> pool.replace(ev.binding(), ev.credential());
            case REMOVED -> pool.close(ev.previous());
        }
    }
}
```

Or give a listener, which receives the events in order on the watch's thread, and keep the `Subscription`:

```java
Subscription sub = client.watch(Filter.all(), WatchOptions.bindingsOnly(), ev -> log.info("{}", ev));
...
sub.cancel();
```

| Event | When | Set |
| :----------------- | :------------------------------------------------------- | :--------------- |
| `ADDED` | A binding appears; at the first poll, every binding. | `binding` |
| `CHANGED` | A binding has another revision. | `binding`, `previous` |
| `REMOVED` | A binding is gone: revoked or expired. | `previous` |
| `CREDENTIAL_ROTATED` | A credential was read for the binding. | `binding`, `credential` |

The semantics are those of the Go `Watch` (chapter "Rotation and revocation"): a little jitter on the poll interval; with `WatchOptions.withCredentials()` the credential is read after `ADDED` and `CHANGED` and again at two thirds of a lease; a failed poll keeps the state, emits nothing and is retried with a backoff that doubles up to five minutes, waiting at least as long as `Retry-After` says; a `ligo` restart is invisible. The iteration ends when you close the `Watch` or the client. `watch.poll(Duration)` returns the next event or nothing after the timeout, for a loop that does other work.

What the application does is the same too: open new connections on `CREDENTIAL_ROTATED`, close the connections of the binding on `REMOVED`, and call `client.invalidate(b)` before reading the credential again when a target refuses it.

The JDK's `HttpClient`, which the REST transport uses, keeps connections alive, so a rotated SVID applies to the connections opened after the rotation. The gRPC transport behaves alike.

## Flows

```java
for (BindingFlows bf : client.flows("orders-db")) {
    for (Flow f : bf.flows()) {
        System.out.println(f.name() + " " + f.protocol() + " " + f.destination() + " " + f.ports() + " " + f.tls());
    }
}
```

`flows` returns data. To see which flow a firewall still blocks before the application connects, test them:

```java
FlowResults results = client.checkFlows("orders-db", FlowOptions.builder().build());
for (FlowResult r : results.unreachable()) {
    System.out.println("blocked: " + r.flow() + " " + r.destination() + " " + r.port() + " " + r.reason());
}
assert results.ok();
```

The check runs when you call it; the SDK never checks on its own. It uses the JDK only, and follows the rules of the Go SDK's `CheckFlows`:

- A TCP flow without TLS is a connection test. A TCP flow with `tls` is checked up to the TLS handshake, verifying the flow's `serverName` (or the destination, when it is a name); `FlowOptions.roots` gives CAs instead of the JDK's. A flow to a bare IP address with `tls` and no `serverName` is skipped: there is no name to verify.
- A flow says `tls` and nothing about how the TLS starts. A flow declared by `ligo` is checked as an X509-SVID against the client's own trust bundle; a flow of a PostgreSQL binding that a target or a platform declares gets PostgreSQL's SSLRequest first. `handshake(...)` overrides the choice (a function of the flow and the port that returns `"postgresql"`, `"spire"` or `null` for plain TLS) and `spiffeBundle(...)` gives another bundle. A SPIFFE flow with no bundle is `UNREACHABLE`.
- A UDP flow passes when no ICMP error comes back, so a silent peer passes: it means "not refused", not "the service is up".
- A destination that is a CIDR, or ports that are a range, are `SKIPPED` with the reason.
- Link-local and cloud metadata addresses are never checked (`deniedNetworks(...)` changes the list). A name is resolved once, each address is vetted, and the check connects to the vetted address. One call runs at most 1,024 checks and throws `TooManyFlows` above that.
- There is no ICMP check.

`FlowCheck.run(flows, options)` tests flows obtained some other way; it takes the options above and `platforms(...)`, the map from a binding's name to its platform type, since it has no client.

## Errors and security

Every exception the SDK throws on purpose derives from the unchecked `LigoException`:

| Exception | Meaning | Do |
| :----------------------- | :------------------------------------------------- | :---------------------- |
| `Unauthorized` | `ligo` refused the caller, or the peer is not `ligo`. | Check the workload's SVID and `serverId`; do not retry blindly. |
| `Unavailable` | `ligo` cannot answer now, limits the caller's rate, or cannot be reached. `retryAfter()` has the delay `ligo` asked for, when it did. | Retry later. |
| `NoCredentialException` | The binding has no secret store. | Connect with the SVID. |
| `UnsupportedStrategy` | The SDK does not know the strategy. | Update the SDK. |
| `StoreNotAllowed` | The store address is not `https`, or is outside `allowedStores`. | Check with the platform team. |
| `StoreError` | The store refused the login or the read, or the binding does not say how to reach it. | The message has the status, never the body. |
| `TooManyFlows` | A flow test would run more than 1,024 checks. | Narrow it with the target. |

Exceptions never hold a password, a token or a JWT.

- **It talks only to `ligo`.** The server is accepted only with `serverId`, over mTLS with TLS 1.3, and the SPIFFE ID is checked in the handshake, before the first byte of the request, on REST and on gRPC. There is no option to skip verification.
- **It sends the JWT-SVID only to a secret store over TLS.** The store address comes from the binding, that is from `ligo`. Set `allowedStores` to the stores your platform team uses, so that a wrong answer cannot lead the SDK to another host.
- **It follows no redirect,** from `ligo` or from a store, because a redirect would carry the SVID or a token to another host. A Vault standby that redirects to the active node therefore fails: use the address of the active node or of a load balancer.
- **It keeps nothing on disk.** The SVID and its key are read from the source in memory, on every handshake; a store token lives in memory until 80 % of its lifetime and is dropped by `close`. Credentials are not cached: the application holds them.
- **It limits what it reads.** An answer over 8 MiB is refused, and every call has a timeout. It reads JSON with default typing off, and never uses Java serialization.
- **It cannot close your connections** after a revocation, and it cannot know that a target has dropped a credential. Handle `REMOVED` and `invalidate`.

## Testing an application

`LigoClient.builder()` takes `x509Source` and `jwtSource`, so a test can give fixed SVIDs and point `address` at a TLS server that speaks the workload API. The SDK's own tests do this, with an in-memory CA: see `sdk/java/src/test`.
