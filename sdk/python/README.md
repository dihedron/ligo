# ligo-client

Python SDK for workloads that use [ligo](https://github.com/dihedron/ligo): it reads the
calling workload's bindings and network flows from ligo's workload API over mTLS with the
workload's SVID, accepting only ligo's SPIFFE ID.

```python
import ligo_client

with ligo_client.Client(address="ligo.example.com:8443", server_id="spiffe://example.com/ns/sys/sa/ligo") as c:
    for b in c.bindings(target="orders-db"):
        print(b.name, b.endpoint(), b.description, b.annotations)
```

REST only and synchronous. Design and threat model: `.specs/ligo-client-sdk-python.md` in the
repository.
