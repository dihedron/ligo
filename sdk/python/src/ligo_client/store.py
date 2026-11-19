"""Reading a binding's credential from a Vault-compatible secret store (.specs/ligo-client-sdk.md §3.3)."""

from __future__ import annotations

import datetime as dt
import http.client
import json
import ssl
from dataclasses import dataclass, field
from typing import Any, NoReturn
from urllib.parse import urlsplit

from .errors import StoreError

MAX_BODY = 8 << 20  # T-C7
CALL_TIMEOUT = 15.0
MAX_LEASE = 100 * 365 * 24 * 3600  # seconds

STATIC = "vault-static"
DYNAMIC = "vault-dynamic"
NONE = "svid"  # of the builtin none.v1 store: the SVID is the credential


@dataclass(frozen=True)
class Credential:
    """What a workload presents to its target. The password is hidden from repr, str, format and logs."""

    username: str
    password: str = field(repr=False)
    expires: dt.datetime | None = None  # None when the store gives no lease

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"Credential(username={self.username!r}, password='[hidden]', expires={self.expires!r})"

    def __format__(self, spec: str) -> str:
        return format(str(self), spec)

    def __copy__(self) -> Credential:
        return self  # immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> Credential:
        return self

    def __reduce__(self) -> NoReturn:
        raise TypeError("a Credential is never pickled: it holds a password")


def store_address(raw: str) -> str:
    """Checks a store address and returns it as https://host:port."""
    try:
        u = urlsplit(raw)
        port = u.port
    except ValueError:
        raise ValueError(f"{raw!r}: https://host:port is required") from None
    if (
        u.scheme != "https"
        or not u.hostname
        or u.username is not None
        or u.password is not None
        or u.path.strip("/")
        or u.query
        or u.fragment
    ):
        raise ValueError(f"{raw!r}: https://host:port is required")
    host = u.hostname.lower()
    return f"https://{'[' + host + ']' if ':' in host else host}:{port or 443}"


def tls_context(roots: str | None) -> ssl.SSLContext:
    """The context for secret stores: the system's roots or `roots`, the name verified, TLS 1.2 or later."""
    ctx = ssl.create_default_context(cafile=roots)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class CallError(Exception):
    """A failed call to a store: the status when there was an answer; never its body."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


def call(
    ctx: ssl.SSLContext,
    address: str,
    method: str,
    path: str,
    *,
    token: str = "",
    namespace: str = "",
    body: dict[str, str] | None = None,
) -> bytes:
    """One call to a store; returns the body of a 200. Redirects are never followed (T-C2)."""
    u = urlsplit(address)
    assert u.hostname is not None  # noqa: S101 - checked by store_address
    headers = {"Accept": "application/json"}
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Vault-Token"] = token
    if namespace:
        headers["X-Vault-Namespace"] = namespace
    conn = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=CALL_TIMEOUT)
    try:
        conn.request(method, "/v1/" + path.lstrip("/"), body=payload, headers=headers)
        resp = conn.getresponse()
        if resp.status != 200:
            raise CallError(f"status {resp.status}", resp.status)
        data = resp.read(MAX_BODY + 1)
        if len(data) > MAX_BODY:
            raise CallError(f"the answer is larger than {MAX_BODY} bytes", 200)
        return data
    except CallError:
        raise
    except ssl.SSLCertVerificationError:
        raise CallError("the store's certificate is not trusted") from None
    except (OSError, http.client.HTTPException) as e:
        raise CallError(f"the call failed: {type(e).__name__}") from None
    finally:
        conn.close()


def _object(data: bytes, what: str) -> dict[str, Any]:
    try:
        doc = json.loads(data)
    except ValueError:
        raise StoreError(f"the answer is not {what}") from None
    if not isinstance(doc, dict):
        raise StoreError(f"the answer is not {what}")
    return doc


def _lease(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > MAX_LEASE:
        raise StoreError("the answer's lease is out of range")
    return v


def parse_login(data: bytes) -> tuple[str, int]:
    """The token of a login answer, and its TTL in seconds."""
    auth = _object(data, "a login").get("auth")
    token = auth.get("client_token") if isinstance(auth, dict) else None
    if not isinstance(token, str) or not token or not isinstance(auth, dict):
        raise StoreError("the answer has no token")
    return token, _lease(auth.get("lease_duration", 0))


def parse_secret(strategy: str, data: bytes, now: float) -> Credential:
    """A KV version 2 secret (vault-static) or database credentials (vault-dynamic)."""
    doc = _object(data, "a secret")
    expires = None
    if strategy == STATIC:
        outer = doc.get("data")
        inner = outer.get("data") if isinstance(outer, dict) else None
    else:
        lease = _lease(doc.get("lease_duration"))
        if lease <= 0:
            raise StoreError("the answer's lease is out of range")
        expires = dt.datetime.fromtimestamp(now + lease, dt.timezone.utc)
        inner = doc.get("data")
    user = inner.get("username") if isinstance(inner, dict) else None
    password = inner.get("password") if isinstance(inner, dict) else None
    if not isinstance(user, str) or not isinstance(password, str) or not user or not password:
        raise StoreError("the answer has no username and password")
    return Credential(user, password, expires)
