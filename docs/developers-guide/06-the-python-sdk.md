# The Python SDK

```python
import ligo_client
```

`ligo-client` is the Python counterpart of the Go SDK of the previous chapters: the same operations, the same data and the same rules, in the idioms of Python. It needs Python 3.10 or later, and depends on [py-spiffe](https://github.com/HewlettPackard/py-spiffe) (`spiffe`) and `cryptography`. It is MIT-licensed, unlike `ligo` itself.

The wheel and the source distribution are attached to each release of `ligo`; install the wheel of the version that matches your `ligo`:

```bash
pip install ./ligo_client-X.Y.Z-py3-none-any.whl
```

The SDK speaks REST only, and is synchronous and safe to use from several threads. There is no gRPC transport (see "Errors and security") and no `asyncio` client; call it from a thread in an `asyncio` program.

## Creating a client

```python
client = ligo_client.Client(
    address="ligo.example.com:8443",                # the workload API: host:port, no scheme
    server_id="spiffe://example.com/ns/sys/sa/ligo",  # the only SPIFFE ID accepted for ligo
)
```

Use it as a context manager (`with ligo_client.Client(...) as client:`) or call `client.close()`. The constructor checks its arguments and raises `ValueError`; it does not call `ligo`. The SVID comes from the SPIRE agent at `SPIFFE_ENDPOINT_SOCKET`, as for every SPIFFE program.

| Argument | Meaning |
| :-------------- | :----------------------------------------------------------------- |
| `address` | `host:port` of the workload API. Always TLS. |
| `server_id` | `ligo`'s SPIFFE ID. Any other peer is refused. |
| `x509_source` | Your own source of the SVID and bundles (a py-spiffe `X509Source`); default: the Workload API. |
| `jwt_source` | Your own source of JWT-SVIDs (a py-spiffe `JwtSource`); default: the Workload API. |
| `store_roots` | The path of a PEM file with the CAs of the secret store's certificate; default: the system's roots. |
| `allowed_stores` | The store addresses (`https://host:port`) the client may log in to. See "Errors and security". |
| `poll_interval` | Seconds between two polls of `watch`; default 30, at least 5. |
| `logger` | A `logging.Logger`; default `logging.getLogger("ligo_client")`. |

## Bindings

```python
bindings = client.bindings(target="orders-db")
if not bindings:
    raise SystemExit("no binding to orders-db")
b = bindings[0]
print(b.name, b.platform_type, b.endpoint())
```

No binding is an empty list, not an error. `bindings` narrows by `target` and by `platform_type`. A `Binding` is a frozen dataclass with the fields of the second chapter in snake case, including `description` and `annotations` (a read-only mapping: both are data, never run them). `spec` is a mapping, since it differs per platform type, and `endpoint()` returns `spec["endpoint"]`, or an empty string.

The client remembers the last answer for each filter and sends its ETag the next time. When nothing has changed, `ligo` answers without a body and the client returns the remembered list, so a call is cheap.

## Credentials

```python
import psycopg

cred = client.credential(b)
host, _, port = b.endpoint().rpartition(":")
conn = psycopg.connect(host=host, port=int(port), dbname=b.spec["database"],
                       user=cred.username, password=cred.password, sslmode="verify-full")
```

`credential` logs in to the secret store with a JWT-SVID and reads the credential of the binding. `cred.expires` is a `datetime` at the end of the lease, or `None` when there is none.

- Every call reads the store. With `vault-dynamic` each read creates a new database user, so read once and keep the result; do not call it for every connection.
- `print(cred)`, `repr(cred)`, `f"{cred}"`, a log line or a traceback never show the password. `Credential` also refuses `pickle`, and `copy` keeps it hidden. Read `cred.password` when you need it.
- A binding that needs no credential (the `svid` strategy) raises `NoCredential`. Connect with the SVID:

```python
sock = client.connect("orders.example.com:5433", "spiffe://example.com/ns/db/sa/orders")
```

`connect` opens an mTLS connection with the workload's SVID, TLS 1.3 only, and returns an `ssl.SSLSocket` to a server that presents exactly the SPIFFE ID you name. The standard library cannot check a peer's SPIFFE ID inside an `SSLContext`, so the SDK gives a function that does it, instead of a context that a caller could use without the check.

## Following rotation and revocation

`watch` is a generator: it polls `ligo` and yields an `Event` for each change. It blocks between polls, so run it on its own thread.

```python
import threading

stop = threading.Event()
for ev in client.watch(target="orders-db", watch_credentials=True, stop=stop):
    if ev.kind in (ligo_client.EventKind.ADDED, ligo_client.EventKind.CHANGED):
        print("binding", ev.binding.name, "revision", ev.binding.revision)
    elif ev.kind is ligo_client.EventKind.CREDENTIAL_ROTATED:
        pool.replace(ev.binding, ev.credential)
    elif ev.kind is ligo_client.EventKind.REMOVED:
        pool.close(ev.previous)
```

| Event | When | Set |
| :----------------- | :------------------------------------------------------- | :--------------- |
| `ADDED` | A binding appears; at the first poll, every binding. | `binding` |
| `CHANGED` | A binding has another revision. | `binding`, `previous` |
| `REMOVED` | A binding is gone: revoked or expired. | `previous` |
| `CREDENTIAL_ROTATED` | A credential was read for the binding. | `binding`, `credential` |

The semantics are those of the Go `Watch` (chapter "Rotation and revocation"): a little jitter on the poll interval; with `watch_credentials` the credential is read after `ADDED` and `CHANGED` and again at two thirds of a lease; a failed poll keeps the state, emits nothing and is retried with a backoff that doubles up to five minutes, waiting at least as long as `Retry-After` says; a `ligo` restart is invisible. The generator ends when you set `stop`, close it, or call `client.close()`.

What the application does is the same too: open new connections on `CREDENTIAL_ROTATED`, close the connections of the binding on `REMOVED`, and call `client.invalidate(b)` before reading the credential again when a target refuses it.

## Flows

```python
for bf in client.flows(target="orders-db"):
    for f in bf.flows:
        print(f.name, f.protocol, f.destination, [(p.low, p.high) for p in f.ports], f.tls)
```

`flows` returns data. To see which flow a firewall still blocks before the application connects, test them:

```python
results = client.check_flows(target="orders-db")
for r in results.unreachable:
    print("blocked:", r.flow, r.destination, r.port, r.reason)
assert results.ok
```

The check runs when you call it; the SDK never checks on its own. It uses the standard library only, and follows the rules of the Go SDK's `CheckFlows`:

- A TCP flow without TLS is a connection test. A TCP flow with `tls` is checked up to the TLS handshake, verifying the flow's `server_name` (or the destination, when it is a name); `roots` gives a PEM file of CAs instead of the system's. A flow to a bare IP address with `tls` and no `server_name` is skipped: there is no name to verify.
- A flow says `tls` and nothing about how the TLS starts. A flow declared by `ligo` is checked as an X509-SVID against the client's own trust bundle; a flow of a PostgreSQL binding that a target or a platform declares gets PostgreSQL's SSLRequest first. `handshake=` overrides the choice (a function of the flow and the port that returns `"postgresql"`, `"spire"` or `None` for plain TLS) and `spiffe_bundle=` gives another bundle. A SPIFFE flow with no bundle is `UNREACHABLE`.
- A UDP flow passes when no ICMP error comes back, so a silent peer passes: it means "not refused", not "the service is up".
- A destination that is a CIDR, or ports that are a range, are `SKIPPED` with the reason.
- Link-local and cloud metadata addresses are never checked (`denied_networks=` changes the list). A name is resolved once, each address is vetted, and the check connects to the vetted address. One call runs at most 1,024 checks and raises `TooManyFlows` above that.
- There is no ICMP check: raw sockets need privileges that a Python program rarely has.

`ligo_client.check_flow_data(flows, ...)` tests flows obtained some other way; it takes the options above and the mapping from `platforms=`, since it has no client.

## Errors and security

Every error the SDK raises on purpose derives from `LigoError`:

| Error | Meaning | Do |
| :----------------------- | :------------------------------------------------- | :---------------------- |
| `Unauthorized` | `ligo` refused the caller, or the peer is not `ligo`. | Check the workload's SVID and `server_id`; do not retry blindly. |
| `Unavailable` | `ligo` cannot answer now, limits the caller's rate, or cannot be reached. `retry_after` has the seconds `ligo` asked for, when it did. | Retry later. |
| `NoCredential` | The binding has no secret store. | Connect with the SVID. |
| `UnsupportedStrategy` | The SDK does not know the strategy. | Update the SDK. |
| `StoreNotAllowed` | The store address is not `https`, or is outside `allowed_stores`. | Check with the platform team. |
| `StoreError` | The store refused the login or the read, or the binding does not say how to reach it. | The message has the status, never the body. |
| `TooManyFlows` | A flow test would run more than 1,024 checks. | Narrow it with `target`. |

Errors never hold a password, a token or a JWT.

- **It talks only to `ligo`.** The server is accepted only with `server_id`, over mTLS with TLS 1.3, and the SPIFFE ID is checked after the handshake and before the first byte of the request. There is no option to skip verification.
- **It sends the JWT-SVID only to a secret store over TLS.** The store address comes from the binding, that is from `ligo`. Set `allowed_stores` to the stores your platform team uses, so that a wrong answer cannot lead the SDK to another host.
- **It follows no redirect,** from `ligo` or from a store, because a redirect would carry the SVID or a token to another host. A Vault standby that redirects to the active node therefore fails: use the address of the active node or of a load balancer.
- **It keeps nothing on disk,** except for an instant: the standard library can load a private key only from a file, so the SDK writes it in a private directory (mode 0700, file 0600) and removes it at once. A store token lives in memory until 80 % of its lifetime and is dropped by `close`. Credentials are not cached: the application holds them.
- **It limits what it reads.** An answer over 8 MiB is refused, and every call has a timeout.
- **Why no gRPC.** The Python gRPC library has no hook to verify a peer by its SPIFFE ID, and `ligo`'s certificate is an SVID with no DNS name, so the SDK could not hold the rule above. REST gives the same data.
- **It cannot close your connections** after a revocation, and it cannot know that a target has dropped a credential. Handle `REMOVED` and `invalidate`.

## Testing an application

`Client` takes `x509_source` and `jwt_source`, so a test can give fixed SVIDs and point `address` at a TLS server that speaks the workload API. The SDK's own tests do this, with an in-memory CA; see `sdk/python/tests/conftest.py`.
