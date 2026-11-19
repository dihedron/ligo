"""mTLS with the workload's SVID, and the check of the server's SPIFFE ID (.specs/ligo-client-sdk-python.md §3.4)."""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import ssl
import tempfile
from typing import Any, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .errors import Unauthorized


class X509Source(Protocol):
    """What spiffe.X509Source gives: the current SVID and the bundle of a trust domain."""

    @property
    def svid(self) -> Any: ...

    def get_bundle_for_trust_domain(self, trust_domain: Any) -> Any: ...


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def build_context(source: X509Source, server_trust_domain: Any) -> tuple[ssl.SSLContext, tuple[bytes, ...]]:
    """A client context with the workload's SVID that trusts the server's trust domain only.

    ssl.SSLContext loads a key and a chain only from files, so they are written to a file of
    mode 0600 in a new directory of mode 0700 and removed before this function returns (T-P1).
    The name of a server is its SPIFFE ID, so the host name is not checked here: see verify_peer.
    The second result identifies the SVID and the bundle the context was built from.
    """
    svid = source.svid
    bundle = source.get_bundle_for_trust_domain(server_trust_domain)
    if svid is None or bundle is None:
        raise Unauthorized("the SPIFFE source has no SVID or no bundle for the server's trust domain")
    authorities = sorted(
        bundle.x509_authorities,
        key=lambda c: c.fingerprint(c.signature_hash_algorithm) if c.signature_hash_algorithm else b"",
    )
    chain = [c.public_bytes(serialization.Encoding.DER) for c in svid.cert_chain]
    fingerprint = (*chain, *(c.public_bytes(serialization.Encoding.DER) for c in authorities))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=b"".join(_pem(c) for c in authorities).decode())

    directory = tempfile.mkdtemp(prefix="ligo-client-")  # mode 0700
    try:
        path = os.path.join(directory, "svid.pem")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(b"".join(_pem(c) for c in svid.cert_chain))
            f.write(
                svid.private_key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )
        ctx.load_cert_chain(path)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return ctx, fingerprint


def current_fingerprint(source: X509Source, server_trust_domain: Any) -> tuple[bytes, ...]:
    svid = source.svid
    bundle = source.get_bundle_for_trust_domain(server_trust_domain)
    if svid is None or bundle is None:
        return ()
    authorities = sorted(bundle.x509_authorities, key=lambda c: c.public_bytes(serialization.Encoding.DER))
    return (
        *(c.public_bytes(serialization.Encoding.DER) for c in svid.cert_chain),
        *(c.public_bytes(serialization.Encoding.DER) for c in authorities),
    )


def verify_peer(tls: ssl.SSLSocket, server_id: str) -> None:
    """The leaf must carry exactly one URI SAN, equal to server_id; otherwise Unauthorized."""
    der = tls.getpeercert(binary_form=True)
    if not der:
        raise Unauthorized("the server presented no certificate")
    try:
        san = x509.load_der_x509_certificate(der).extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (x509.ExtensionNotFound, ValueError):
        raise Unauthorized("the server's certificate has no SPIFFE ID") from None
    uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or uris[0] != server_id:
        raise Unauthorized("the server's SPIFFE ID is not the one this client accepts")


def connect(ctx: ssl.SSLContext, host: str, port: int, server_id: str, timeout: float) -> ssl.SSLSocket:
    """Connect, run the handshake, check the server's ID, and only then give the socket back."""
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except ssl.SSLCertVerificationError:
        raw.close()
        raise Unauthorized("the server's certificate is not trusted by the workload's bundle") from None
    except BaseException:
        raw.close()
        raise
    try:
        verify_peer(tls, server_id)
    except BaseException:
        with contextlib.suppress(OSError):
            tls.close()
        raise
    return tls
