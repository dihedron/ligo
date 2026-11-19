# SPDX-License-Identifier: MIT
"""Testing the flows of the bindings (.specs/ligo-client-sdk-python.md §5, .specs/ligo-network-checks.md §9).

Written on the standard library: a TCP connect, a TLS handshake verified by name, PostgreSQL's
SSLRequest, an X509-SVID verified against a trust bundle, and a UDP datagram. Nothing runs unless
check_flows or check_flow_data is called.
"""

from __future__ import annotations

import enum
import ipaddress
import logging
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .errors import TooManyFlows
from .types import BindingFlows, Flow

MAX_FLOW_CHECKS = 1024
POSTGRESQL = "postgresql"
SPIRE = "spire"
SSL_REQUEST = bytes([0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F])  # PostgreSQL's SSLRequest

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
DEFAULT_DENIED: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::/32"),
)

Handshake = Callable[[Flow, int], str | None]


class FlowStatus(str, enum.Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    SKIPPED = "skipped"  # the flow could not be checked, which is not a failure

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class FlowResult:
    """The outcome of one flow and port."""

    binding: str = ""
    target: str = ""
    flow: str = ""
    destination: str = ""
    port: int = 0
    protocol: str = ""  # tcp, tls, postgresql, spire, udp; empty when skipped before a check was chosen
    status: FlowStatus = FlowStatus.SKIPPED
    reason: str = ""  # why it is unreachable or skipped; for a UDP pass, what the pass means
    error: BaseException | None = None  # the check's error when unreachable
    latency: float = 0.0  # seconds
    attempts: int = 0


class FlowResults(list[FlowResult]):
    """The outcome of a call."""

    @property
    def unreachable(self) -> FlowResults:
        return FlowResults(r for r in self if r.status == FlowStatus.UNREACHABLE)

    @property
    def ok(self) -> bool:
        """No flow is unreachable. Skipped flows do not count."""
        return not self.unreachable


class _Denied(Exception):
    pass


@dataclass
class _Item:
    result: FlowResult
    key: tuple[str, str, int, str] | None = None  # protocol, host, port, server name; None: skipped
    proto: str = ""
    name: str = ""


def _addr(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _denies(denied: Iterable[IPNetwork], ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in denied)


def _plan(
    bf: BindingFlows, choose: Callable[[BindingFlows, Flow, int], str | None], denied: Sequence[IPNetwork]
) -> list[_Item]:
    items: list[_Item] = []
    for f in bf.flows:
        base = FlowResult(binding=bf.binding, target=bf.target, flow=f.name, destination=f.destination)

        def skip(port: int, why: str, base: FlowResult = base) -> None:
            items.append(
                _Item(FlowResult(**{**base.__dict__, "port": port, "status": FlowStatus.SKIPPED, "reason": why}))
            )

        proto = f.protocol.upper()
        if proto not in ("TCP", "UDP"):
            skip(0, f"protocol {f.protocol!r} is not checkable")
            continue
        if "/" in f.destination:
            skip(0, "a CIDR destination has no single host to check")
            continue
        if not f.destination:
            skip(0, "no destination")
            continue
        if not f.ports:
            skip(0, "no ports")
            continue
        ip = _addr(f.destination)
        for p in f.ports:
            if p.low != p.high:
                skip(p.low, f"the port range {p.low}-{p.high} is not probed")
                continue
            if not 1 <= p.low <= 65535:
                skip(p.low, f"port {p.low} is not valid")
                continue
            if ip is not None and _denies(denied, ip):
                skip(p.low, "the destination is in a denied network")
                continue
            host = f.destination.strip("[]")
            r = FlowResult(**{**base.__dict__, "port": p.low})
            if proto == "UDP":
                kind, name = "udp", ""
            elif f.tls and choose(bf, f, p.low) == SPIRE:
                kind, name = SPIRE, ""  # an SVID has no name to verify
            elif f.tls:
                name = f.server_name or ("" if ip is not None else f.destination)
                if not name:
                    skip(p.low, "tls with a bare IP address and no server name: there is no name to verify")
                    continue
                kind = POSTGRESQL if choose(bf, f, p.low) == POSTGRESQL else "tls"
            else:
                kind, name = "tcp", ""
            r = FlowResult(**{**r.__dict__, "protocol": kind})
            items.append(_Item(r, (kind, host, p.low, name), kind, name))
    return items


@dataclass
class _Options:
    timeout: float
    retries: int
    retry_delay: float
    roots: str | None
    denied: Sequence[IPNetwork]
    bundle: Any
    spiffe_id: str | None
    stop: threading.Event | None
    tls: ssl.SSLContext = field(init=False)

    def __post_init__(self) -> None:
        self.tls = ssl.create_default_context(cafile=self.roots)


def _resolve(host: str, port: int, kind: int, o: _Options) -> list[str]:
    """The addresses of host that are not denied. The check connects to these, never to the name again."""
    ip = _addr(host)
    if ip is not None:
        return [str(ip)]
    try:
        infos = socket.getaddrinfo(host, port, type=kind)
    except OSError as e:
        raise OSError(f"cannot resolve {host}: {e}") from None
    ok: list[str] = []
    for info in infos:
        a = _addr(str(info[4][0]))
        if a is not None and not _denies(o.denied, a) and str(a) not in ok:
            ok.append(str(a))
    if not ok:
        raise _Denied
    return ok


def _connect(addresses: list[str], port: int, timeout: float) -> socket.socket:
    last: OSError | None = None
    for a in addresses:
        s = socket.socket(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((a, port))
        except OSError as e:
            s.close()
            last = e
            continue
        return s
    assert last is not None  # noqa: S101 - addresses is not empty
    raise last


def _check_once(item: _Item, o: _Options) -> str:
    """One attempt; raises when the flow is unreachable. Returns a note for the reason of a pass."""
    assert item.key is not None  # noqa: S101
    kind, host, port, name = item.key
    if kind == "udp":
        addresses = _resolve(host, port, socket.SOCK_DGRAM, o)
        family = socket.AF_INET6 if ":" in addresses[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(o.timeout)
            s.connect((addresses[0], port))
            s.send(b"\x00")
            try:
                s.recv(1)
            except TimeoutError:
                return "no ICMP error came back; a silent peer passes"
            return ""
    sock = _connect(_resolve(host, port, socket.SOCK_STREAM, o), port, o.timeout)
    try:
        if kind == "tcp":
            return ""
        if kind == POSTGRESQL:
            sock.sendall(SSL_REQUEST)
            answer = sock.recv(1)
            if answer == b"E":
                raise ConnectionError("the server answered the SSLRequest with an error")
            if answer != b"S":
                raise ConnectionError("the server does not offer TLS")
        if kind == SPIRE:
            _spire(sock, o)
            return ""
        with o.tls.wrap_socket(sock, server_hostname=name) as tls:
            tls.do_handshake()
        return ""
    finally:
        sock.close()


def _spire(sock: socket.socket, o: _Options) -> None:
    """The server's chain is verified against the bundle; its ID must belong to the bundle's trust domain."""
    if o.bundle is None:
        raise ssl.SSLError("no trust bundle to verify the SVID with")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False  # NOSONAR: the SPIFFE ID is checked after the handshake; SVIDs carry no DNS name
    ctx.verify_mode = ssl.CERT_REQUIRED
    pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in o.bundle.x509_authorities)
    if not pem:
        raise ssl.SSLError("the trust bundle has no authorities")
    ctx.load_verify_locations(cadata=pem)
    with ctx.wrap_socket(sock) as tls:
        der = tls.getpeercert(binary_form=True)
        if not der:
            raise ssl.SSLError("the server presented no certificate")
        san = x509.load_der_x509_certificate(der).extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        if len(uris) != 1:
            raise ssl.SSLError("the certificate is not an X509-SVID: it has no single URI SAN")
        sid = uris[0]
        domain = getattr(o.bundle.trust_domain, "name", str(o.bundle.trust_domain))
        if not sid.startswith(f"spiffe://{domain}/"):
            raise ssl.SSLError("the SPIFFE ID is not in the bundle's trust domain")
        if o.spiffe_id is not None and sid != o.spiffe_id:
            raise ssl.SSLError("the SPIFFE ID is not the expected one")


def _run(item: _Item, o: _Options) -> FlowResult:
    r = item.result
    last: BaseException | None = None
    start = time.monotonic()
    attempts = 0
    for attempt in range(1, max(1, o.retries) + 1):
        if o.stop is not None and o.stop.is_set():
            return FlowResult(
                **{**r.__dict__, "status": FlowStatus.SKIPPED, "reason": "interrupted", "attempts": attempts}
            )
        attempts = attempt
        start = time.monotonic()
        try:
            note = _check_once(item, o)
        except _Denied:
            return FlowResult(
                **{**r.__dict__, "status": FlowStatus.SKIPPED, "reason": "the destination is in a denied network"}
            )
        except (OSError, ssl.SSLError, ConnectionError) as e:
            last = e
            if attempt < o.retries and o.retry_delay > 0:
                time.sleep(o.retry_delay)
            continue
        return FlowResult(
            **{
                **r.__dict__,
                "status": FlowStatus.REACHABLE,
                "reason": note,
                "latency": time.monotonic() - start,
                "attempts": attempt,
            }
        )
    reason = str(last) or type(last).__name__
    if isinstance(last, ssl.SSLCertVerificationError):
        reason = last.verify_message or reason
    return FlowResult(
        **{
            **r.__dict__,
            "status": FlowStatus.UNREACHABLE,
            "reason": reason,
            "error": last,
            "latency": time.monotonic() - start,
            "attempts": attempts,
        }
    )


def default_handshake(platforms: Mapping[str, str]) -> Callable[[BindingFlows, Flow, int], str | None]:
    """A flow declared by ligo is an SVID; a PostgreSQL binding's target or platform flow is PostgreSQL's."""

    def choose(bf: BindingFlows, f: Flow, port: int) -> str | None:
        if f.declared_by == "ligo":
            return SPIRE
        platform = platforms.get(bf.binding, "")
        if (platform == "postgres" or platform.startswith("postgres.")) and f.declared_by.startswith(
            ("target:", "platform:")
        ):
            return POSTGRESQL
        return None

    return choose


def check_flow_data(
    flows: Sequence[BindingFlows],
    *,
    timeout: float = 5.0,
    retries: int = 2,
    retry_delay: float = 0.2,
    concurrency: int = 8,
    roots: str | None = None,
    denied_networks: Iterable[IPNetwork] | None = None,
    handshake: Handshake | None = None,
    spiffe_bundle: Any = None,
    spiffe_id: str | None = None,
    platforms: Mapping[str, str] | None = None,
    logger: logging.Logger | None = None,
    stop: threading.Event | None = None,
) -> FlowResults:
    """Tests flows obtained elsewhere.

    A TCP flow is a connection test, or a TLS handshake when the flow says tls; a UDP flow passes when no
    ICMP error comes back, which means "not refused", not "the service is up"; a CIDR destination or a
    port range is skipped, with its reason. A flow does not say how its TLS starts: `handshake(flow,
    port)` returns "postgresql" or "spire" (None: plain TLS); the default is the Go SDK's, which needs
    `platforms` (binding name to platform type) to know PostgreSQL bindings. A "spire" flow is verified
    against `spiffe_bundle` (any ID of its trust domain, or `spiffe_id`); without a bundle it is unreachable.
    `roots` is a CA file for TLS flows (default: the system's). The check connects to an address it has
    vetted against `denied_networks` (default: link-local and cloud metadata ranges), never to a name again.
    ICMP is not supported. Raises TooManyFlows above MAX_FLOW_CHECKS checks.
    """
    denied = tuple(DEFAULT_DENIED if denied_networks is None else denied_networks)
    choose: Callable[[BindingFlows, Flow, int], str | None]
    if handshake is not None:
        user = handshake

        def choose(bf: BindingFlows, f: Flow, port: int) -> str | None:
            return user(f, port)
    else:
        choose = default_handshake(platforms or {})
    items: list[_Item] = []
    for bf in flows:
        items.extend(_plan(bf, choose, denied))
    if len(items) > MAX_FLOW_CHECKS:
        raise TooManyFlows(f"too many flows to check: {len(items)} checks, at most {MAX_FLOW_CHECKS}")
    o = _Options(timeout, retries, retry_delay, roots, denied, spiffe_bundle, spiffe_id, stop)

    unique: dict[tuple[str, str, int, str], _Item] = {}
    for it in items:
        if it.key is not None:
            unique.setdefault(it.key, it)
    done: dict[tuple[str, str, int, str], FlowResult] = {}
    if unique:
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            for key, res in zip(unique, pool.map(lambda it: _run(it, o), unique.values()), strict=True):
                done[key] = res
    out = FlowResults()
    for it in items:
        if it.key is None:
            r = it.result
        else:
            d = done[it.key]
            r = FlowResult(
                **{
                    **d.__dict__,
                    "binding": it.result.binding,
                    "target": it.result.target,
                    "flow": it.result.flow,
                    "destination": it.result.destination,
                }
            )
        out.append(r)
        if logger is not None:
            logger.debug(
                "flow checked: binding=%s flow=%s destination=%s port=%s protocol=%s status=%s reason=%s",
                r.binding,
                r.flow,
                r.destination,
                r.port,
                r.protocol,
                r.status.value,
                r.reason,
            )
    return out
