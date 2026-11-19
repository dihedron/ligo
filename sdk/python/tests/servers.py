# SPDX-License-Identifier: MIT
"""Small servers for flow testing: TCP, TLS, PostgreSQL's SSLRequest, and UDP."""

from __future__ import annotations

import contextlib
import datetime
import socket
import ssl
import tempfile
import threading
import types
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .conftest import CA, _now

SSL_REQUEST = bytes([0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F])


def server_context(ca: CA, dns: str | None = None, spiffe_id: str | None = None) -> ssl.SSLContext:
    """A server context whose certificate is signed by ca and names a DNS name or a SPIFFE ID."""
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = []
    if dns:
        names.append(x509.DNSName(dns))
    if spiffe_id:
        names.append(x509.UniformResourceIdentifier(spiffe_id))
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "flow")]))
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(minutes=30))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(ca.key, hashes.SHA256())
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as d:
        pem = Path(d, "s.pem")
        pem.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        ctx.load_cert_chain(pem)
    return ctx


class Listener:
    """A TCP listener on 127.0.0.1 that runs `serve(conn)` for each connection."""

    def __init__(self, serve: types.FunctionType | None = None) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port: int = self.sock.getsockname()[1]
        self.accepted = 0
        self._serve = serve
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            if self._serve is not None:
                self._serve(conn)
        except (OSError, ssl.SSLError):
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def close(self) -> None:
        self.sock.close()


def tls_server(ctx: ssl.SSLContext) -> Listener:
    def serve(conn: socket.socket) -> None:
        tls = ctx.wrap_socket(conn, server_side=True)
        tls.recv(1)

    return Listener(serve)  # type: ignore[arg-type]


def postgres_server(ctx: ssl.SSLContext, answer: bytes = b"S") -> Listener:
    """Answers an SSLRequest with `answer`; on S, serves TLS."""

    def serve(conn: socket.socket) -> None:
        req = b""
        while len(req) < 8:
            chunk = conn.recv(8 - len(req))
            if not chunk:
                return
            req += chunk
        if req != SSL_REQUEST:
            return
        conn.sendall(answer)
        if answer == b"S":
            tls = ctx.wrap_socket(conn, server_side=True)
            tls.recv(1)

    return Listener(serve)  # type: ignore[arg-type]


class UdpSilent:
    """A UDP socket that reads and never answers."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port: int = self.sock.getsockname()[1]

    def close(self) -> None:
        self.sock.close()


def closed_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port: int = s.getsockname()[1]
    s.close()
    return port


def closed_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port: int = s.getsockname()[1]
    s.close()
    return port
