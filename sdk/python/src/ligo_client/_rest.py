"""One conditional GET of the workload API, over mTLS, with the server's ID checked before the request."""

from __future__ import annotations

import http.client
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

from . import _tls
from .errors import LigoError, Unauthorized, Unavailable

MAX_BODY = 8 << 20  # T-C7
MAX_RETRY_AFTER = 3600  # seconds; a longer one is ignored
CALL_TIMEOUT = 15.0


def get(
    context: Callable[[], Any], host: str, port: int, server_id: str, path: str, query: dict[str, str], etag: str
) -> tuple[list[Any], str, bool]:
    """Returns (items, etag, not_modified)."""
    url = path + ("?" + urlencode(query) if query else "")
    headers = {"Accept": "application/json", "Host": f"{host}:{port}"}
    if etag:
        headers["If-None-Match"] = etag
    try:
        tls = _tls.connect(context(), host, port, server_id, CALL_TIMEOUT)
    except Unauthorized:
        raise
    except OSError as e:  # includes ssl.SSLError and timeouts
        raise Unavailable(f"cannot reach ligo: {type(e).__name__}") from None
    conn = http.client.HTTPConnection(host, port, timeout=CALL_TIMEOUT)
    conn.sock = tls  # the ID is checked: the first byte of the request goes out now
    try:
        conn.request("GET", url, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        if status == 304:
            return [], etag, True
        if status in (401, 403):
            raise Unauthorized(f"ligo refused the workload: {status}")
        if status in (503, 429):
            raise Unavailable(f"ligo is unavailable: {status}", retry_after=_retry_after(resp.getheader("Retry-After")))
        if status != 200:
            raise LigoError(f"unexpected answer: {status}")
        body = resp.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise LigoError(f"the answer is larger than {MAX_BODY} bytes")
        new_etag = resp.getheader("ETag") or ""
    except (OSError, http.client.HTTPException) as e:
        raise Unavailable(f"the call to ligo failed: {type(e).__name__}") from None
    finally:
        conn.close()
    try:
        doc = json.loads(body)
    except ValueError:
        raise LigoError("the answer is not a JSON document") from None
    items = doc.get("items") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise LigoError("the answer has no list of items")
    return items, new_etag, False


def _retry_after(value: str | None) -> float | None:
    try:
        n = int(value) if value is not None else 0
    except ValueError:
        return None
    return float(n) if 0 < n <= MAX_RETRY_AFTER else None
