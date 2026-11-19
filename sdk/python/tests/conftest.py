# SPDX-License-Identifier: MIT
"""An in-memory CA and in-process TLS servers: the tests need no SPIRE agent."""

from __future__ import annotations

import contextlib
import datetime
import ipaddress
import json
import socket
import ssl
import tempfile
import threading
import types
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from spiffe import SpiffeId, TrustDomain, X509Bundle, X509Svid

LIGO_ID = "spiffe://prod.lab/ns/sys/sa/ligo"
WORKER_ID = "spiffe://prod.lab/ns/e2e/sa/worker"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class CA:
    """A certificate authority for one trust domain."""

    def __init__(self, trust_domain: str = "prod.lab") -> None:
        self.trust_domain = trust_domain
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{trust_domain} CA")])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(hours=1))
            .not_valid_after(_now() + datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def svid(self, spiffe_id: str) -> X509Svid:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=5))
            .not_valid_after(_now() + datetime.timedelta(minutes=30))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), critical=True)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        return X509Svid(SpiffeId(spiffe_id), [cert], key)

    def bundle(self) -> X509Bundle:
        return X509Bundle(TrustDomain(self.trust_domain), {self.cert})


class StaticSource:
    """What spiffe.X509Source gives: the current SVID and the bundles."""

    def __init__(self, ca: CA, spiffe_id: str = WORKER_ID) -> None:
        self.ca = ca
        self.svid = ca.svid(spiffe_id)
        self.closed = False

    def rotate(self, spiffe_id: str) -> None:
        self.svid = self.ca.svid(spiffe_id)

    def get_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> X509Bundle:
        return self.ca.bundle()

    def close(self) -> None:
        self.closed = True


@dataclass
class Request:
    method: str
    target: str
    headers: dict[str, str]
    peer: str  # the SPIFFE ID of the client certificate


Response = tuple[int, dict[str, str], bytes]


@dataclass
class Server:
    """A TLS server that requires a client SVID and answers with a handler."""

    ca: CA
    svid: X509Svid
    handler: Callable[[Request], Response]
    requests: list[Request] = field(default_factory=list)
    raw_bytes: int = 0  # what clients sent after a successful handshake, parsed or not
    handshakes: int = 0
    port: int = 0
    _sock: socket.socket | None = None
    _thread: threading.Thread | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    def start(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=self.ca.cert.public_bytes(serialization.Encoding.PEM).decode())
        with tempfile.TemporaryDirectory() as d:
            chain = Path(d, "chain.pem")
            chain.write_bytes(
                b"".join(c.public_bytes(serialization.Encoding.PEM) for c in self.svid.cert_chain)
                + self.svid.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            ctx.load_cert_chain(chain)
        self._ctx = ctx
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._sock is not None:
            self._sock.close()

    def _serve(self) -> None:
        assert self._sock is not None
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close()
            return
        with self._lock:
            self.handshakes += 1
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(65536)
                if not chunk:
                    return
                data += chunk
                with self._lock:
                    self.raw_bytes += len(chunk)
            head = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
            method, target, _ = head[0].split(" ", 2)
            headers = {k.lower(): v.strip() for k, v in (h.split(":", 1) for h in head[1:])}
            der = tls.getpeercert(binary_form=True)
            assert der is not None
            san = x509.load_der_x509_certificate(der).extensions.get_extension_for_class(x509.SubjectAlternativeName)
            peer = san.value.get_values_for_type(x509.UniformResourceIdentifier)[0]
            req = Request(method, target, headers, peer)
            with self._lock:
                self.requests.append(req)
            status, extra, body = self.handler(req)
            lines = [f"HTTP/1.1 {status} X", f"Content-Length: {len(body)}", "Connection: close"]
            lines += [f"{k}: {v}" for k, v in extra.items()]
            tls.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
        except (ssl.SSLError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                tls.close()


@pytest.fixture
def ca() -> CA:
    return CA()


@pytest.fixture
def source(ca: CA) -> StaticSource:
    return StaticSource(ca)


@pytest.fixture
def serve(ca: CA) -> Iterator[Callable[..., Server]]:
    """serve(handler, spiffe_id=LIGO_ID) starts a server and stops it after the test."""
    started: list[Server] = []

    def make(handler: Callable[[Request], Response], spiffe_id: str = LIGO_ID, *, with_ca: CA | None = None) -> Server:
        issuer = with_ca or ca
        s = Server(ca, issuer.svid(spiffe_id), handler)
        s.start()
        started.append(s)
        return s

    yield make
    for s in started:
        s.stop()


@dataclass
class StoreRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict[str, Any]:
        out: dict[str, Any] = json.loads(self.body)
        return out


StoreResponse = tuple[int, dict[str, str], bytes]


class StoreServer:
    """A secret store: HTTPS with a server certificate for 127.0.0.1, no client certificate."""

    def __init__(self, ca: CA, handler: Callable[[StoreRequest], StoreResponse]) -> None:
        self.handler = handler
        self.requests: list[StoreRequest] = []
        self._lock = threading.Lock()
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "store")]))
            .issuer_name(ca.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=5))
            .not_valid_after(_now() + datetime.timedelta(minutes=30))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False)
            .sign(ca.key, hashes.SHA256())
        )
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with tempfile.TemporaryDirectory() as d:
            pem = Path(d, "store.pem")
            pem.write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
                + key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )
            self._ctx.load_cert_chain(pem)
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self._sock.close()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close()
            return
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            headers = {k.lower(): v.strip() for k, v in (h.split(":", 1) for h in lines[1:])}
            want = int(headers.get("content-length", "0"))
            while len(rest) < want:
                rest += tls.recv(65536)
            req = StoreRequest(method, path, headers, rest)
            with self._lock:
                self.requests.append(req)
            status, extra, body = self.handler(req)
            out = [f"HTTP/1.1 {status} X", f"Content-Length: {len(body)}", "Connection: close"]
            out += [f"{k}: {v}" for k, v in extra.items()]
            tls.sendall(("\r\n".join(out) + "\r\n\r\n").encode() + body)
        except (ssl.SSLError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                tls.close()


@pytest.fixture
def store(ca: CA) -> Iterator[Callable[[Callable[[StoreRequest], StoreResponse]], StoreServer]]:
    started: list[StoreServer] = []

    def make(handler: Callable[[StoreRequest], StoreResponse], with_ca: CA | None = None) -> StoreServer:
        s = StoreServer(with_ca or ca, handler)
        started.append(s)
        return s

    yield make
    for s in started:
        s.stop()


@pytest.fixture
def ca_file(ca: CA, tmp_path: Path) -> str:
    p = tmp_path / "ca.pem"
    p.write_bytes(ca.cert.public_bytes(serialization.Encoding.PEM))
    return str(p)


class FakeJwt:
    """What spiffe.JwtSource gives: a token for an audience."""

    def __init__(self) -> None:
        self.calls: list[tuple[set[str], str]] = []
        self.closed = False

    def fetch_svid(self, audience: set[str], subject: Any = None, timeout: float | None = None) -> Any:
        self.calls.append((set(audience), str(subject)))
        (aud,) = audience
        return types.SimpleNamespace(token=f"jwt-for-{aud}")

    def close(self) -> None:
        self.closed = True
