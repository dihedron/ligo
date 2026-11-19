# SPDX-License-Identifier: MIT
"""PY-1 to PY-4 and PY-13 (.specs/ligo-client-sdk-python.md §6)."""

from __future__ import annotations

import json
import os
import ssl
import stat
import tempfile
import time
from collections.abc import Callable
from typing import cast

import pytest

import ligo_client
from ligo_client import Client, LigoError, Unauthorized, Unavailable

from .conftest import CA, LIGO_ID, Request, Response, Server, StaticSource

BINDINGS = {
    "callerSpiffeId": "spiffe://prod.lab/ns/e2e/sa/worker",
    "items": [
        {
            "id": "0192",
            "name": "workers-ledger",
            "source": "workers",
            "target": "ledger",
            "accessLevel": "write",
            "platformType": "postgres",
            "platform": "pg-prod",
            "revision": 4,
            "updatedAt": "2026-10-16T07:02:11Z",
            "description": "Ledger posting",
            "annotations": {"change": "CHG0012345"},
            "auth": {
                "secretStorageStrategy": "vault-static",
                "secretStoreType": "vault",
                "secretStoreInstance": "vault-prod",
                "config": {
                    "address": "https://vault.lab:8200",
                    "audience": "https://vault.lab",
                    "authMount": "jwt",
                    "role": "binding-0192",
                    "policy": "binding-0192",
                    "secretPath": "kv/data/bindings/0192",
                },
            },
            "spec": {"endpoint": "db.lab:5432", "database": "ledger", "port": 5432},
        }
    ],
}


def ok(doc: object, etag: str = '"sha256:aa"') -> Response:
    return 200, {"Content-Type": "application/json", "ETag": etag}, json.dumps(doc).encode()


def client(server: Server, source: StaticSource, **kw: object) -> Client:
    return Client(address=server.address, server_id=LIGO_ID, x509_source=source, **kw)  # type: ignore[arg-type]


# PY-1
@pytest.mark.parametrize(
    ("kw", "want"),
    [
        ({"address": ""}, "address"),
        ({"address": "https://ligo.lab:8443"}, "address"),
        ({"address": "ligo.lab"}, "address"),
        ({"address": "ligo.lab:99999"}, "address"),
        ({"address": ":8443"}, "address"),
        ({"server_id": ""}, "server_id"),
        ({"server_id": "ligo"}, "server_id"),
        ({"poll_interval": 4.0}, "poll_interval"),
    ],
)
def test_constructor_refuses(kw: dict[str, object], want: str, source: StaticSource) -> None:
    args: dict[str, object] = {"address": "ligo.lab:8443", "server_id": LIGO_ID, "x509_source": source}
    args.update(kw)
    with pytest.raises(ValueError, match=want):
        Client(**args)  # type: ignore[arg-type]


def test_constructor_does_not_call_ligo(source: StaticSource) -> None:
    # no server listens on this port, and nothing is dialed
    with Client(address="127.0.0.1:1", server_id=LIGO_ID, x509_source=source):
        pass
    assert not source.closed  # a source the caller gave is the caller's to close


# PY-2
def test_bindings_decode(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: ok(BINDINGS))
    with client(s, source) as c:
        got = c.bindings(target="ledger", platform_type="postgres")
    assert s.requests[0].target == "/v1/bindings?target=ledger&platformType=postgres"
    assert s.requests[0].peer == "spiffe://prod.lab/ns/e2e/sa/worker"
    [b] = got
    assert (b.id, b.name, b.source, b.target, b.access_level) == (
        "0192",
        "workers-ledger",
        "workers",
        "ledger",
        "write",
    )
    assert (b.platform_type, b.platform, b.revision) == ("postgres", "pg-prod", 4)
    assert b.updated_at is not None and b.updated_at.isoformat() == "2026-10-16T07:02:11+00:00"
    assert b.spec == {"endpoint": "db.lab:5432", "database": "ledger", "port": 5432}
    assert b.endpoint() == "db.lab:5432"
    assert b.description == "Ledger posting" and b.annotations == {"change": "CHG0012345"}
    assert b.auth.strategy == "vault-static" and b.auth.store_type == "vault"
    assert b.auth.store_instance == "vault-prod"
    assert b.auth.config["secretPath"] == "kv/data/bindings/0192"


def test_empty_is_not_an_error(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: ok({"callerSpiffeId": "x", "items": []}))
    with client(s, source) as c:
        assert c.bindings() == []


def test_annotations_are_a_copy(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: ok(BINDINGS))
    with client(s, source) as c:
        first = c.bindings()
        cast(dict[str, str], first[0].annotations)["change"] = "changed"  # the map is not shared
        assert c.bindings()[0].annotations["change"] == "CHG0012345"


def test_absent_text_is_empty(serve: Callable[..., Server], source: StaticSource) -> None:
    doc = json.loads(json.dumps(BINDINGS))
    del doc["items"][0]["description"], doc["items"][0]["annotations"]
    s = serve(lambda r: ok(doc))
    with client(s, source) as c:
        [b] = c.bindings()
    assert b.description == "" and b.annotations == {}


def test_endpoint_without_one(serve: Callable[..., Server], source: StaticSource) -> None:
    doc = json.loads(json.dumps(BINDINGS))
    doc["items"][0]["spec"] = {"port": 5432}
    s = serve(lambda r: ok(doc))
    with client(s, source) as c:
        assert c.bindings()[0].endpoint() == ""


def test_flows_decode(serve: Callable[..., Server], source: StaticSource) -> None:
    doc = {
        "callerSpiffeId": "x",
        "items": [
            {
                "binding": "b",
                "source": "s",
                "target": "t",
                "flows": [
                    {
                        "name": "db",
                        "purpose": "DATA",
                        "protocol": "TCP",
                        "destination": "db.lab",
                        "ports": [5432, "6000-6010"],
                        "tls": True,
                        "serverName": "db.lab",
                        "description": "d",
                        "declaredBy": "target:t",
                    }
                ],
            }
        ],
    }
    s = serve(lambda r: ok(doc))
    with client(s, source) as c:
        [bf] = c.flows(target="t")
    assert s.requests[0].target == "/v1/flows?target=t"
    [f] = bf.flows
    assert (bf.binding, bf.source, bf.target) == ("b", "s", "t")
    assert [(p.low, p.high) for p in f.ports] == [(5432, 5432), (6000, 6010)]
    assert f.tls and f.server_name == "db.lab" and f.declared_by == "target:t" and f.purpose == "DATA"


def test_bad_port_is_refused(serve: Callable[..., Server], source: StaticSource) -> None:
    doc = {"items": [{"binding": "b", "flows": [{"name": "x", "ports": ["nope"]}]}]}
    s = serve(lambda r: ok(doc))
    with client(s, source) as c, pytest.raises(LigoError):
        c.flows()


# PY-3
def test_etag_and_not_modified(serve: Callable[..., Server], source: StaticSource) -> None:
    def handler(r: Request) -> Response:
        if r.headers.get("if-none-match") == '"sha256:aa"':
            return 304, {}, b""
        return ok(BINDINGS)

    s = serve(handler)
    with client(s, source) as c:
        first = c.bindings(target="ledger")
        again = c.bindings(target="ledger")
        other = c.bindings(target="other")  # another filter has its own ETag
    assert again == first and other == first
    assert "if-none-match" not in s.requests[0].headers
    assert s.requests[1].headers["if-none-match"] == '"sha256:aa"'
    assert "if-none-match" not in s.requests[2].headers


# PY-4
def test_other_server_id_gets_no_request(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: ok(BINDINGS), spiffe_id="spiffe://prod.lab/ns/evil/sa/ligo")
    with client(s, source) as c, pytest.raises(Unauthorized):
        c.bindings()
    time.sleep(0.3)  # a late read on the server would show here
    assert s.raw_bytes == 0 and s.requests == []  # nothing was sent after the handshake


def test_untrusted_server_is_unauthorized(source: StaticSource, serve: Callable[..., Server]) -> None:
    s = serve(lambda r: ok(BINDINGS), with_ca=CA())  # another CA signed it
    with client(s, source) as c, pytest.raises((Unauthorized, Unavailable)):
        c.bindings()
    assert s.requests == []


@pytest.mark.parametrize("status", [503, 429])
def test_unavailable_with_retry_after(status: int, serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: (status, {"Retry-After": "7"}, b"busy"))
    with client(s, source) as c, pytest.raises(Unavailable) as e:
        c.bindings()
    assert e.value.retry_after == 7
    assert "busy" not in str(e.value)  # a message holds a status, never a body


@pytest.mark.parametrize("header", ["", "soon", "-3", "0", "999999"])
def test_retry_after_is_ignored_when_unusable(header: str, serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: (503, {"Retry-After": header} if header else {}, b""))
    with client(s, source) as c, pytest.raises(Unavailable) as e:
        c.bindings()
    assert e.value.retry_after is None


@pytest.mark.parametrize("status", [401, 403])
def test_refused_is_unauthorized(status: int, serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: (status, {}, b"no"))
    with client(s, source) as c, pytest.raises(Unauthorized):
        c.bindings()


def test_unexpected_status(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: (500, {}, b"boom"))
    with client(s, source) as c, pytest.raises(LigoError) as e:
        c.bindings()
    assert not isinstance(e.value, (Unauthorized, Unavailable)) and "500" in str(e.value)


def test_not_a_document(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: (200, {}, b"<html>"))
    with client(s, source) as c, pytest.raises(LigoError):
        c.bindings()


def test_no_server_is_unavailable(source: StaticSource) -> None:
    with Client(address="127.0.0.1:1", server_id=LIGO_ID, x509_source=source) as c, pytest.raises(Unavailable):
        c.bindings()


def test_a_redirect_is_not_followed(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: (302, {"Location": "https://elsewhere.example/"}, b""))
    with client(s, source) as c, pytest.raises(LigoError):
        c.bindings()
    assert len(s.requests) == 1


# PY-13
def test_body_over_the_limit(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: (200, {}, b" " * ((8 << 20) + 1)))
    with client(s, source) as c, pytest.raises(LigoError) as e:
        c.bindings()
    assert not isinstance(e.value, Unavailable)


# T-P1: the key is on the disk only while the context loads, in a private file
def test_key_file_is_private_and_removed(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., Server], source: StaticSource
) -> None:
    seen: list[tuple[int, int, str]] = []
    real = ssl.SSLContext.load_cert_chain

    def spy(self: ssl.SSLContext, certfile: str, keyfile: str | None = None, password: object = None) -> None:
        p = os.fspath(certfile)
        seen.append((stat.S_IMODE(os.stat(p).st_mode), stat.S_IMODE(os.stat(os.path.dirname(p)).st_mode), p))
        real(self, certfile, keyfile, password)  # type: ignore[arg-type]

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", spy)
    s = serve(lambda r: ok(BINDINGS))
    with client(s, source) as c:
        c.bindings()
    seen = [
        x for x in seen if os.path.basename(os.path.dirname(x[2])).startswith("ligo-client-")
    ]  # the server loads a chain too
    assert seen and all(m == 0o600 and d == 0o700 for m, d, _ in seen)
    assert not any(os.path.exists(p) for _, _, p in seen)
    assert not [n for n in os.listdir(tempfile.gettempdir()) if n.startswith("ligo-client-")]


# rotation: the context follows the source
def test_rotation_rebuilds_the_context(serve: Callable[..., Server], source: StaticSource) -> None:
    s = serve(lambda r: ok(BINDINGS))
    with client(s, source) as c:
        c.bindings()
        source.rotate("spiffe://prod.lab/ns/e2e/sa/worker2")
        c.bindings()
    assert [r.peer for r in s.requests] == ["spiffe://prod.lab/ns/e2e/sa/worker", "spiffe://prod.lab/ns/e2e/sa/worker2"]


def test_threads(serve: Callable[..., Server], source: StaticSource) -> None:
    import concurrent.futures as cf

    s = serve(lambda r: ok(BINDINGS))
    with client(s, source) as c, cf.ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: c.bindings(), range(32)))
    assert all(r == results[0] for r in results)


def test_exports() -> None:
    assert {
        "Client",
        "LigoError",
        "Unauthorized",
        "Unavailable",
        "NoCredential",
        "UnsupportedStrategy",
        "StoreNotAllowed",
        "StoreError",
    } <= set(ligo_client.__all__)


# the replacement of Go's TLSConfig: an mTLS connection that accepts one server ID only
def test_connect_accepts_only_the_given_id(serve: Callable[..., Server], source: StaticSource) -> None:
    target = "spiffe://prod.lab/ns/db/sa/orders"
    good = serve(lambda r: ok({"items": []}), spiffe_id=target)
    bad = serve(lambda r: ok({"items": []}), spiffe_id="spiffe://prod.lab/ns/db/sa/other")
    with Client(address="127.0.0.1:1", server_id=LIGO_ID, x509_source=source) as c:
        with c.connect(good.address, target) as tls:
            assert tls.version() == "TLSv1.3"
        with pytest.raises(Unauthorized):
            c.connect(bad.address, target)


def test_closed_client_refuses(source: StaticSource) -> None:
    c = Client(address="127.0.0.1:1", server_id=LIGO_ID, x509_source=source)
    c.close()
    with pytest.raises(RuntimeError):
        c.bindings()
