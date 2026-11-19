# The Python client SDK

- **Version:** 0.2 (2026-11-19): `connect` replaces `tls_context` (§3.2); 0.1 (2026-11-19), approved by the user in plan mode
- **Backlog:** item 7 (Python), items 20 to 24
- **Branch:** `feature/python-sdk` (specs), `feature/python-sdk-core` (chunk 1)
- **Depends on:** `.specs/ligo-client-sdk.md` (the Go SDK; everything not said here is the same), `.specs/ligo-network-checks.md` §9 (flow testing in both SDKs)

## 1. Why

A Python workload does by hand the steps the Go SDK does (`.specs/ligo-client-sdk.md` §1): fetch its SVID, call the workload API over mTLS accepting only ligo's SPIFFE ID, read the binding, fetch a JWT-SVID, log in to the store, read the credential, do it again at rotation. The Developer's Guide has promised a Python SDK since the Go one shipped (`docs/developers-guide/06-other-languages.md`).

## 2. Decisions (the user, 2026-11-19)

| Question | Decision |
|---|---|
| Where | `sdk/python/` in the ligo repository: one version, one CI, one release. |
| Transport | REST only, synchronous. gRPC is left out because Python's `grpcio` cannot verify the server's SPIFFE ID: ligo's certificate is an SVID with a URI SAN and no DNS name, and `grpcio` has no hook for custom peer verification. An asyncio client is a later item. |
| Publishing | Wheel and sdist attached to the GitHub release. PyPI later (backlog 22). |
| Flow testing | Built into the client in both SDKs (`Client.check_flows` here, `Client.CheckFlows` in Go), not a separate package. |

## 3. The package

PyPI name `ligo-client` (free on 2026-11-19), import `ligo_client`, Python 3.10 or later (the floor of `py-spiffe`), typed (`py.typed`). One runtime dependency, `spiffe` (`py-spiffe` 0.4.0, which brings `grpcio` and `cryptography` for the Workload API). HTTP and TLS use the standard library (`http.client`, `ssl`).

```python
import ligo_client

with ligo_client.Client(address="ligo1.example.com:8443",
                        server_id="spiffe://example.com/ns/sys/sa/ligo",
                        allowed_stores=["https://vault.example.com"]) as c:
    for b in c.bindings(target="orders-db"):
        cred = c.credential(b)
    for ev in c.watch(target="orders-db", watch_credentials=True):
        ...
    results = c.check_flows(target="orders-db")
```

### 3.1 The client

`Client(address, server_id, *, x509_source=None, jwt_source=None, store_roots=None, allowed_stores=(), poll_interval=30.0, logger=None)`. The arguments are those of the Go `Config` (§3.1 there): `address` is `host:port`, TLS always; `server_id` is the only SPIFFE ID accepted for ligo; `poll_interval` is never under 5 s. `x509_source` and `jwt_source` take any object with the `py-spiffe` interface (default: `spiffe.X509Source` and `spiffe.JwtSource` on `SPIFFE_ENDPOINT_SOCKET`, opened on first use and closed by `close()`); tests and the lab give static ones. The constructor validates and does not call ligo. The client is thread-safe and a context manager.

### 3.2 Operations

| Method | Go | Notes |
|---|---|---|
| `bindings(target=None, platform_type=None) -> list[Binding]` | `Bindings` | ETag kept per filter, `If-None-Match`, "not modified" returns the remembered list; an empty list is not an error. |
| `flows(target=None) -> list[BindingFlows]` | `Flows` | Data only. |
| `credential(binding) -> Credential` | `Credential` | `vault-static` and `vault-dynamic`; JWT-SVID for `auth.config.audience`; login at `auth/<authMount>/login`; read of `secretPath` (KV v2) or `credsPath`; `X-Vault-Namespace` when the binding has a namespace; store token reused to 80 % of its TTL; one new login and one retry on a 403; `NoCredential` for strategy `svid`. |
| `invalidate(binding)` | `Invalidate` | Drops the remembered store token. |
| `connect(address, server_id, *, timeout=15) -> ssl.SSLSocket` | `TLSConfig` | An mTLS connection with the workload's SVID, TLS 1.3, to a server that presents `server_id` only (§3.4). It is not a `tls_context`: the standard library has no hook to check a peer's SPIFFE ID inside an `SSLContext`, so the check runs after the handshake, in `connect`, and a bare context would let a caller skip it (T-P5). |
| `watch(target=None, platform_type=None, *, watch_credentials=False, stop=None)` | `Watch` | A blocking generator of `Event` (`kind` `added`, `changed`, `removed`, `credential_rotated`; `binding`, `previous`, `credential`). It ends when the generator is closed, `close()` is called, or the `threading.Event` `stop` is set. Poll cadence, jitter, backoff to 5 minutes and `Retry-After` as the Go SDK (§3.5). |
| `check_flows(target=None, **options) -> FlowResults` and `check_flow_data(flows, **options)` | `CheckFlows`, `CheckFlowData` | §5. |
| `close()` | `Close` | Drops the store tokens, closes the sources it opened. |

`Binding` (with `description` and `annotations`, a copy of the map, see `.specs/ligo-binding-annotations.md`), `Auth`, `Credential`, `Event`, `Flow`, `BindingFlows` are frozen dataclasses with the Go fields in snake case. `Binding.endpoint()` returns `spec["endpoint"]` when it is a string. `Credential` hides its password in `__repr__`, `__str__`, `__format__`, logging and `copy`, and refuses to be pickled.

### 3.3 Errors

`LigoError` is the base. `Unauthorized`, `Unavailable`, `NoCredential`, `UnsupportedStrategy`, `StoreNotAllowed`, `StoreError` carry the meaning of the Go sentinels (§3.6 there). `Unavailable` has `retry_after` (seconds, or `None`). A message holds a status, never a body, a token or a password.

### 3.4 TLS

- **The context.** `ssl.SSLContext` loads a key and chain only from files, so the SVID goes to a file in a new directory of mode 0700, mode 0600, and both are removed before `load_cert_chain` returns to the caller. The bundle's CAs are loaded with `cadata`. TLS 1.3 only; `verify_mode` is `CERT_REQUIRED` and `check_hostname` is false, since the name is the SPIFFE ID.
- **The ID check.** After the handshake and before the first byte of the request, the leaf must carry exactly one URI SAN, equal to `server_id`; otherwise the socket is closed and `Unauthorized` is raised. No option skips the check or the verification.
- **Rotation.** The context is rebuilt when the source's SVID or bundle changes.
- **The store.** Its own context from `store_roots` (default: the system's), `https` only, pinned by `allowed_stores`, no redirect followed, response bodies limited to 8 MiB, a 15 s timeout.

## 4. Threat model

The Go rows T-C1 to T-C8 apply. New:

| ID | Threat | Mitigation |
|---|---|---|
| T-P1 | The private key reaches the disk. | Only for the instant of `load_cert_chain`: a 0700 directory, a 0600 file, removed at once; never logged. |
| T-P2 | A server that is not ligo receives the request. | The ID is checked before the first write; tested with a server of another ID. |
| T-P3 | A secret in `repr`, a traceback, a log, a copy or a pickle. | `Credential` hides it everywhere above; errors carry statuses. |
| T-P4 | Supply chain: `py-spiffe`, `grpcio`, `cryptography`. | A bounded range in `pyproject.toml`, `pip-audit` and dependency review in CI, a hash-pinned lock file for development, the wheel built in CI from the tag. |
| T-P5 | A flag that turns verification off. | None exists. |
| T-P6 | `check_flows` is used to scan. | As T-N1: destinations are those the server vetted against `allowed_endpoints`; link-local and metadata ranges denied by default; a CIDR or a range is never expanded; 1,024 checks at most. |

## 5. Flow testing

`check_flows` reads the flows and tests them; `check_flow_data` tests flows from another source. The same semantics as Go (`.specs/ligo-network-checks.md` §3 and §9): one result per flow and port, `FlowResult` with `binding`, `target`, `flow`, `destination`, `port`, `protocol` (`tcp`, `tls`, `postgresql`, `spire`, `udp`), `status` (`reachable`, `unreachable`, `skipped`), `reason`, `error`, `latency`, `attempts`; `FlowResults` has `ok` and `unreachable`. Written on the standard library:

| Flow | Check |
|---|---|
| TCP | `socket` connect to the resolved address. |
| TCP, `tls` | A TLS handshake, the name verified against the system roots or `roots=`; a bare IP with no `serverName` is skipped. |
| PostgreSQL | `SSLRequest`, `S`, then the TLS handshake as above. |
| SPIFFE | The chain verified against the client's X.509 bundle (any ID of the trust domain, or `spiffe_id=`); no name. |
| UDP | A datagram on a connected socket; an ICMP error is `ConnectionRefusedError`; a silent peer passes, and the reason says so. |

Defaults: 5 s a try, 2 tries, 8 at a time (`ThreadPoolExecutor`), 1,024 checks, link-local and metadata ranges denied (`denied_networks=`). The check connects to the IP it vetted, so a DNS answer cannot lead elsewhere. The handshake of a flow is chosen by `handshake=callable(flow, port)`; the default is the one of the Go SDK: a flow declared by `ligo` is SPIFFE, a flow of a PostgreSQL binding is PostgreSQL. ICMP is not in the Python SDK (raw sockets need privileges): backlog 21.

## 6. Tests first

`pytest`, with an in-memory CA and in-process TLS servers (`tests/conftest.py`). The numbers follow the Go spec's CS-n.

- **PY-1** the constructor refuses what the Go `New` refuses.
- **PY-2** `bindings` decodes `spec` and `auth`; an empty list is not an error.
- **PY-3** the second call sends the ETag and returns the remembered list on 304.
- **PY-4** a server with another SPIFFE ID gets no request (`Unauthorized`); 503 and 429 are `Unavailable` with `retry_after`.
- **PY-6, PY-7** `credential` on `vault-static` and `vault-dynamic`.
- **PY-8** store-token reuse, one retry on 403, `invalidate`.
- **PY-9** `NoCredential`, `UnsupportedStrategy`, `StoreNotAllowed`, an `http` store, a store certificate outside `store_roots`, a binding with no audience.
- **PY-10** no log line, error, `repr`, `str`, `copy` or pickle holds the password, the token or the JWT.
- **PY-11, PY-12** `watch`: events in order, rotation at two thirds of a lease, state kept through failed polls, backoff, `Retry-After`, stop.
- **PY-13** a body over 8 MiB is refused.
- **PY-15** the namespace goes on the login and the read.
- **PY-F1 to PY-F9** flow testing, as the Go FC-1 to FC-12: the mapping, reachable and unreachable, TLS trusted, untrusted and wrong name, a fake PostgreSQL, a fake SVID server, denied networks, the limit, no secret in logs.
- **PY-G** golden documents in `api/testdata/workload/` (`bindings.json`, `flows.json`, `store-*.json`) decoded by the Go and the Python tests to equal values.
- Fuzz (`hypothesis`) on a bindings document and a store response. A benchmark of `bindings` answered 304.

Lab (the release-run, on OpenBao and Vault):

- **PY-L1** a Python echo client (`test/lab/echo/client-py`) as `echo-bound` on ligo1 passes `lab.sh echo smoke` for both echo targets, with the real SPIRE agent.
- **PY-L2** `lab.sh serve test-python`: a `vault-dynamic` PostgreSQL binding, as `TestServeClientSDK`: `added`, a credential that connects, then `removed` and a refused credential.
- **PY-L3** the flow scenario of Go's `FC-L1` to `FC-L5` in Python, with the same block of the database host for the test's group.

## 7. CI, build and release

- `.github/workflows/ci.yml` gets a `python` job on 3.10 to 3.13: `ruff`, `mypy --strict`, `pytest` with coverage, `pip-audit`. CodeQL covers Python.
- `make py-test`, `py-lint`, `py-build`. `make lint` stays Go.
- The version is the ligo tag: the build reads it from git; `0.0.0.dev0` without a tag.
- The release workflow builds the wheel and the sdist from the tag and attaches them with their checksums; the signed `checksums.txt` covers them.

## 8. Documentation

A Developer's Guide chapter, "The Python SDK" (client, bindings, credential, connecting with `psycopg`, watch, revocation, flow testing, errors, security: `allowed_stores`, the ID check, why no gRPC); `06-other-languages.md` keeps Java and JavaScript/TypeScript; the Architecture and Design Guide gets the SDK in the component view and the T-P rows; the README; `sdk/python/README.md`.

## 9. Chunks

| Chunk | Content |
|---|---|
| 0 | This spec, `.specs/ligo-network-checks.md` §9, the backlog. |
| 0b | Go: `flowcheck` moves into `pkg/client` as `Client.CheckFlows` (§9 of the network-checks spec). |
| 1 | The package, `Client`, the mTLS context and the ID check, `bindings`, `flows` (PY-1 to PY-4, PY-13). |
| 2 | `credential`, the store, errors, fuzz (PY-6 to PY-10, PY-15). |
| 3 | `watch` (PY-11, PY-12), `check_flows` (PY-F), the golden documents (PY-G), the benchmark. |
| 4 | CI, `make` targets, the release wiring. |
| 5 | The lab (PY-L1 to PY-L3), the guide, the READMEs. |
| 6 | The PR. |

## 10. Out of scope

gRPC, asyncio, connection reuse, ICMP in flow testing, PyPI, signing or attesting the wheel (backlog items 20 to 24), Java and JavaScript/TypeScript.
