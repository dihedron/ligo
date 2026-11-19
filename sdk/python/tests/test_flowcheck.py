# SPDX-License-Identifier: MIT
"""PY-F1 to PY-F9: flow testing (.specs/ligo-client-sdk-python.md §5, .specs/ligo-network-checks.md §9)."""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization

from ligo_client import (
    BindingFlows,
    Client,
    Flow,
    FlowResults,
    FlowStatus,
    LigoError,
    PortRange,
    TooManyFlows,
    check_flow_data,
)

from .conftest import CA, LIGO_ID, Request, Response, Server, StaticSource
from .servers import (
    Listener,
    UdpSilent,
    closed_tcp_port,
    closed_udp_port,
    postgres_server,
    server_context,
    tls_server,
)

NAME = "db.test"


def flow(port: int, **kw: object) -> Flow:
    base: dict[str, object] = {
        "name": "f",
        "protocol": "TCP",
        "destination": "127.0.0.1",
        "ports": (PortRange(port, port),),
    }
    base.update(kw)
    return Flow(**base)  # type: ignore[arg-type]


def bf(*flows: Flow, binding: str = "b", target: str = "t") -> list[BindingFlows]:
    return [BindingFlows(binding=binding, source="s", target=target, flows=tuple(flows))]


@pytest.fixture
def ca_pem(ca: CA, tmp_path: Path) -> str:
    p = tmp_path / "flow-ca.pem"
    p.write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM))
    return str(p)


@pytest.fixture
def listeners() -> Iterator[list[Listener]]:
    made: list[Listener] = []
    yield made
    for m in made:
        m.close()


def tcp(listeners: list[Listener]) -> Listener:
    ln = Listener()
    listeners.append(ln)
    return ln


def fast(**kw: Any) -> dict[str, Any]:
    return {"timeout": 2.0, "retries": 1, **kw}


# PY-F1: one result per flow and port, with what the check did
def test_tcp_reachable_and_unreachable(listeners: list[Listener]) -> None:
    ln = tcp(listeners)
    flows = bf(flow(ln.port, name="open"), flow(closed_tcp_port(), name="closed"))
    res = check_flow_data(flows, **fast())  # type: ignore[arg-type]
    by = {r.flow: r for r in res}
    assert by["open"].status == FlowStatus.REACHABLE and by["open"].protocol == "tcp"
    assert by["open"].port == ln.port and by["open"].attempts == 1 and by["open"].latency >= 0
    assert (by["open"].binding, by["open"].target, by["open"].destination) == ("b", "t", "127.0.0.1")
    assert by["closed"].status == FlowStatus.UNREACHABLE and by["closed"].error is not None and by["closed"].reason
    assert not res.ok and [r.flow for r in res.unreachable] == ["closed"]
    assert FlowResults([by["open"]]).ok


def test_each_port_is_a_result(listeners: list[Listener]) -> None:
    a, b = tcp(listeners), tcp(listeners)
    f = Flow(
        name="two",
        protocol="TCP",
        destination="127.0.0.1",
        ports=(PortRange(a.port, a.port), PortRange(b.port, b.port)),
    )
    res = check_flow_data(bf(f), **fast())  # type: ignore[arg-type]
    assert sorted(r.port for r in res) == sorted([a.port, b.port]) and res.ok


def test_retries_are_counted() -> None:
    res = check_flow_data(bf(flow(closed_tcp_port())), timeout=1.0, retries=3, retry_delay=0.0)
    assert res[0].attempts == 3 and res[0].status == FlowStatus.UNREACHABLE


# PY-F2: TLS, trusted, untrusted, wrong name
def test_tls_trusted_untrusted_wrong_name(ca: CA, ca_pem: str, listeners: list[Listener]) -> None:
    ln = tls_server(server_context(ca, dns=NAME))
    listeners.append(ln)
    f = flow(ln.port, tls=True, server_name=NAME)
    assert check_flow_data(bf(f), roots=ca_pem, **fast())[0].status == FlowStatus.REACHABLE  # type: ignore[arg-type]
    assert check_flow_data(bf(f), roots=ca_pem, **fast())[0].protocol == "tls"  # type: ignore[arg-type]
    untrusted = check_flow_data(bf(f), **fast())[0]  # type: ignore[arg-type]
    assert untrusted.status == FlowStatus.UNREACHABLE  # the system roots do not know the CA
    wrong = check_flow_data(bf(flow(ln.port, tls=True, server_name="other.test")), roots=ca_pem, **fast())[0]  # type: ignore[arg-type]
    assert wrong.status == FlowStatus.UNREACHABLE
    other_ca = CA()
    stranger = tls_server(server_context(other_ca, dns=NAME))
    listeners.append(stranger)
    assert (
        check_flow_data(bf(flow(stranger.port, tls=True, server_name=NAME)), roots=ca_pem, **fast())[0].status
        == FlowStatus.UNREACHABLE
    )  # type: ignore[arg-type]


def test_tls_to_a_bare_ip_is_skipped(listeners: list[Listener]) -> None:
    r = check_flow_data(bf(flow(tcp(listeners).port, tls=True)), **fast())[0]  # type: ignore[arg-type]
    assert r.status == FlowStatus.SKIPPED and "no name to verify" in r.reason


# PY-F3: a fake PostgreSQL
def test_postgresql_handshake(ca: CA, ca_pem: str, listeners: list[Listener]) -> None:
    pg = postgres_server(server_context(ca, dns=NAME))
    listeners.append(pg)
    f = flow(pg.port, tls=True, server_name=NAME)
    plain = check_flow_data(bf(f), roots=ca_pem, **fast())[0]  # type: ignore[arg-type]
    assert plain.status == FlowStatus.UNREACHABLE  # a plain TLS check of a PostgreSQL port fails
    r = check_flow_data(bf(f), roots=ca_pem, handshake=lambda fl, port: "postgresql", **fast())[0]  # type: ignore[arg-type]
    assert r.status == FlowStatus.REACHABLE and r.protocol == "postgresql"
    untrusted = check_flow_data(bf(f), handshake=lambda fl, port: "postgresql", **fast())[0]  # type: ignore[arg-type]
    assert untrusted.status == FlowStatus.UNREACHABLE
    no_tls = postgres_server(server_context(ca, dns=NAME), answer=b"N")
    listeners.append(no_tls)
    refused = check_flow_data(
        bf(flow(no_tls.port, tls=True, server_name=NAME)),
        roots=ca_pem,
        handshake=lambda fl, port: "postgresql",
        **fast(),
    )[0]  # type: ignore[arg-type]
    assert refused.status == FlowStatus.UNREACHABLE and "TLS" in refused.reason


# PY-F4: a fake SVID server
def test_spiffe_handshake(ca: CA, source: StaticSource, listeners: list[Listener]) -> None:
    svid = server_context(ca, spiffe_id="spiffe://prod.lab/ns/sys/sa/ligo")
    ln = tls_server(svid)
    listeners.append(ln)
    f = flow(ln.port, tls=True)
    bundle = ca.bundle()
    choose = lambda fl, port: "spire"  # noqa: E731
    r = check_flow_data(bf(f), handshake=choose, spiffe_bundle=bundle, **fast())[0]  # type: ignore[arg-type]
    assert r.status == FlowStatus.REACHABLE and r.protocol == "spire"
    exact = check_flow_data(
        bf(f), handshake=choose, spiffe_bundle=bundle, spiffe_id="spiffe://prod.lab/ns/sys/sa/ligo", **fast()
    )[0]  # type: ignore[arg-type]
    assert exact.status == FlowStatus.REACHABLE
    wrong_id = check_flow_data(
        bf(f), handshake=choose, spiffe_bundle=bundle, spiffe_id="spiffe://prod.lab/ns/sys/sa/other", **fast()
    )[0]  # type: ignore[arg-type]
    assert wrong_id.status == FlowStatus.UNREACHABLE
    none = check_flow_data(bf(f), handshake=choose, **fast())[0]  # type: ignore[arg-type]
    assert none.status == FlowStatus.UNREACHABLE and "no trust bundle" in none.reason
    other = CA("other.lab")
    wrong_bundle = check_flow_data(bf(f), handshake=choose, spiffe_bundle=other.bundle(), **fast())[0]  # type: ignore[arg-type]
    assert wrong_bundle.status == FlowStatus.UNREACHABLE
    # a certificate of another trust domain's name, signed by this CA: not a member
    foreign = tls_server(server_context(ca, spiffe_id="spiffe://elsewhere.lab/x"))
    listeners.append(foreign)
    assert (
        check_flow_data(bf(flow(foreign.port, tls=True)), handshake=choose, spiffe_bundle=bundle, **fast())[0].status
        == FlowStatus.UNREACHABLE
    )  # type: ignore[arg-type]


# PY-F5: UDP
def test_udp() -> None:
    quiet = UdpSilent()
    try:
        f = flow(quiet.port, protocol="UDP", name="quiet")
        r = check_flow_data(bf(f), timeout=0.5, retries=1)[0]
        assert r.status == FlowStatus.REACHABLE and r.protocol == "udp" and "silent peer passes" in r.reason
    finally:
        quiet.close()
    refused = check_flow_data(bf(flow(closed_udp_port(), protocol="UDP")), timeout=1.0, retries=1)[0]
    assert refused.status == FlowStatus.UNREACHABLE


# PY-F6: what is skipped, and why
@pytest.mark.parametrize(
    ("f", "why"),
    [
        (Flow(name="x", protocol="SCTP", destination="127.0.0.1", ports=(PortRange(1, 1),)), "not checkable"),
        (Flow(name="x", protocol="TCP", destination="10.0.0.0/8", ports=(PortRange(5432, 5432),)), "CIDR"),
        (Flow(name="x", protocol="TCP", destination="", ports=(PortRange(5432, 5432),)), "no destination"),
        (Flow(name="x", protocol="TCP", destination="127.0.0.1", ports=()), "no ports"),
        (Flow(name="x", protocol="TCP", destination="127.0.0.1", ports=(PortRange(6000, 6010),)), "range"),
        (Flow(name="x", protocol="TCP", destination="127.0.0.1", ports=(PortRange(0, 0),)), "not valid"),
    ],
)
def test_skipped_flows(f: Flow, why: str) -> None:
    [r] = check_flow_data(bf(f), **fast())  # type: ignore[arg-type]
    assert r.status == FlowStatus.SKIPPED and why in r.reason and r.protocol in ("", "tcp")
    assert FlowResults([r]).ok  # skipped is not a failure


# PY-F7: denied networks, and no packet to them
@pytest.mark.parametrize("dest", ["169.254.169.254", "fe80::1", "fd00:ec2::254"])
def test_denied_networks_get_no_packet(dest: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise AssertionError("a packet went to a denied network")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    [r] = check_flow_data(bf(flow(80, destination=dest)), **fast())  # type: ignore[arg-type]
    assert r.status == FlowStatus.SKIPPED and "denied" in r.reason


def test_a_name_that_resolves_to_a_denied_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
    )
    [r] = check_flow_data(bf(flow(80, destination="metadata.internal")), **fast())  # type: ignore[arg-type]
    assert r.status == FlowStatus.SKIPPED and "denied" in r.reason


def test_the_check_connects_to_the_address_it_vetted(
    listeners: list[Listener], monkeypatch: pytest.MonkeyPatch
) -> None:
    ln = tcp(listeners)
    calls = []

    def fake(host: str, port: int, *a: object, **k: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    [r] = check_flow_data(bf(flow(ln.port, destination="db.internal")), **fast())  # type: ignore[arg-type]
    assert r.status == FlowStatus.REACHABLE and calls == ["db.internal"]  # one resolution, used for the connection


def test_denied_networks_can_be_replaced(listeners: list[Listener]) -> None:
    ln = tcp(listeners)
    [r] = check_flow_data(bf(flow(ln.port)), denied_networks=[ipaddress.ip_network("127.0.0.0/8")], **fast())  # type: ignore[arg-type]
    assert r.status == FlowStatus.SKIPPED
    [r] = check_flow_data(bf(flow(ln.port)), denied_networks=[], **fast())  # type: ignore[arg-type]
    assert r.status == FlowStatus.REACHABLE


# PY-F8: the limit, and stopping
def test_too_many_checks() -> None:
    many = Flow(name="m", protocol="TCP", destination="127.0.0.1", ports=tuple(PortRange(p, p) for p in range(1, 1026)))
    with pytest.raises(TooManyFlows):
        check_flow_data(bf(many))
    assert issubclass(TooManyFlows, LigoError)


def test_a_stopped_call_skips_the_rest(listeners: list[Listener]) -> None:
    stop = threading.Event()
    stop.set()
    [r] = check_flow_data(bf(flow(tcp(listeners).port)), stop=stop, **fast())  # type: ignore[arg-type]
    assert r.status == FlowStatus.SKIPPED and r.reason == "interrupted"


def test_equal_checks_run_once(listeners: list[Listener]) -> None:
    ln = tcp(listeners)
    res = check_flow_data(bf(flow(ln.port, name="a"), flow(ln.port, name="b")), **fast())  # type: ignore[arg-type]
    assert [r.status for r in res] == [FlowStatus.REACHABLE] * 2
    assert ln.accepted == 1


# PY-F9: no secret in the logs
def test_logs_name_the_flow_and_hold_nothing_else(listeners: list[Listener], caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="ligo_client")
    check_flow_data(
        bf(flow(tcp(listeners).port), flow(closed_tcp_port(), name="closed")),
        logger=logging.getLogger("ligo_client"),
        **fast(),
    )  # type: ignore[arg-type]
    assert any("flow checked" in r.getMessage() for r in caplog.records)
    for r in caplog.records:
        assert "PRIVATE KEY" not in r.getMessage() and "token" not in r.getMessage().lower()


# the client: the defaults come from what the client knows
def test_check_flows_chooses_the_handshakes(
    ca: CA, source: StaticSource, serve: Callable[..., Server], listeners: list[Listener], ca_pem: str
) -> None:
    pg = postgres_server(server_context(ca, dns=NAME))
    svid = tls_server(server_context(ca, spiffe_id=LIGO_ID))
    plain = tcp(listeners)
    listeners.extend([pg, svid])
    docs = {
        "/v1/flows": {
            "items": [
                {
                    "binding": "b",
                    "source": "s",
                    "target": "t",
                    "flows": [
                        {
                            "name": "db",
                            "protocol": "TCP",
                            "destination": "127.0.0.1",
                            "ports": [pg.port],
                            "tls": True,
                            "serverName": NAME,
                            "declaredBy": "target:t",
                        },
                        {
                            "name": "ligo",
                            "protocol": "TCP",
                            "destination": "127.0.0.1",
                            "ports": [svid.port],
                            "tls": True,
                            "declaredBy": "ligo",
                        },
                        {
                            "name": "store",
                            "protocol": "TCP",
                            "destination": "127.0.0.1",
                            "ports": [plain.port],
                            "declaredBy": "secret-store:vault",
                        },
                    ],
                }
            ]
        },
        "/v1/bindings": {"items": [{"id": "1", "name": "b", "target": "t", "platformType": "postgres.v1"}]},
    }
    import json

    def handler(r: Request) -> Response:
        path = r.target.split("?")[0]
        return 200, {"ETag": '"x"'}, json.dumps(docs[path]).encode()

    s = serve(handler)
    with Client(address=s.address, server_id=LIGO_ID, x509_source=source) as c:
        res = c.check_flows(target="t", roots=ca_pem, **fast())  # type: ignore[arg-type]
        assert {r.flow: (r.protocol, r.status) for r in res} == {
            "db": ("postgresql", FlowStatus.REACHABLE),
            "ligo": ("spire", FlowStatus.REACHABLE),
            "store": ("tcp", FlowStatus.REACHABLE),
        }
        assert [r.target for r in res] == ["t"] * 3
        docs["/v1/bindings"]["items"][0]["platformType"] = "oracle.v1"  # type: ignore[index]
        res = c.check_flows(target="t", roots=ca_pem, **fast())  # type: ignore[arg-type]
        assert {r.flow: r.protocol for r in res}[
            "db"
        ] == "tls"  # another platform: plain TLS, which fails on PostgreSQL
        assert {r.flow: r.status for r in res}["db"] == FlowStatus.UNREACHABLE
        overridden = c.check_flows(
            target="t", roots=ca_pem, handshake=lambda fl, port: "postgresql" if fl.name == "db" else None, **fast()
        )  # type: ignore[arg-type]
        assert {r.flow: r.status for r in overridden}["db"] == FlowStatus.REACHABLE
