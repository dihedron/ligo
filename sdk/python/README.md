# ligo-client

Python SDK for workloads that use [ligo](https://github.com/dihedron/ligo): it reads the
calling workload's bindings and network flows from ligo's workload API over mTLS with the
workload's SVID, accepting only ligo's SPIFFE ID; it takes the binding's credential from the
secret store with a JWT-SVID; and it follows rotation and revocation.

Python 3.10 or later; depends on `spiffe` (py-spiffe) and `cryptography`. REST only and
synchronous; safe to use from several threads. MIT license.

## Install

The wheel and the source distribution are attached to each release of ligo (they are not on
PyPI yet). Install the wheel of the version that matches your ligo:

```bash
pip install ./ligo_client-X.Y.Z-py3-none-any.whl
```

## Use

```python
import threading

import ligo_client

with ligo_client.Client(address="ligo.example.com:8443", server_id="spiffe://example.com/ns/sys/sa/ligo") as client:
    for b in client.bindings(target="orders-db"):
        print(b.name, b.endpoint(), b.description, b.annotations)
        cred = client.credential(b)  # a Credential; its password never shows in repr or logs

    stop = threading.Event()
    for ev in client.watch(target="orders-db", watch_credentials=True, stop=stop):
        ...  # ADDED, CHANGED, REMOVED, CREDENTIAL_ROTATED

    results = client.check_flows(target="orders-db")
    assert results.ok, results.unreachable
```

The Developer's Guide has the chapter "The Python SDK": the client's arguments, credentials
and `psycopg`, watch, flow testing, the errors, and what the SDK protects. Design and threat
model: `.specs/ligo-client-sdk-python.md` in the repository.

## Develop

```bash
pip install -e "sdk/python[dev]"
make py-lint py-test py-build      # from the repository root
```

The tests need no ligo: they run an in-memory CA and in-process TLS servers. The golden
documents in `api/testdata/workload/` are decoded by both the Go and the Python tests.
