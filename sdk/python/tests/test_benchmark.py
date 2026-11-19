# SPDX-License-Identifier: MIT
"""Benchmark of Client.bindings() answered 304 (.specs/ligo-client-sdk-python.md §6).

Skipped unless LIGO_BENCH=1:  LIGO_BENCH=1 python -m pytest tests/test_benchmark.py -s
It reports the median and the 99th percentile of one call over a TLS 1.3 connection to an in-process server,
and fails only when the median is far above what a keep-alive-less request needs (a regression guard).
"""

from __future__ import annotations

import os
import statistics
import time
from collections.abc import Callable

import pytest

from ligo_client import Client

from .conftest import LIGO_ID, Request, Response, Server, StaticSource

CALLS = 500
MEDIAN_LIMIT_MS = 50.0  # generous: a handshake and a request on loopback take a few milliseconds


@pytest.mark.skipif(os.environ.get("LIGO_BENCH") != "1", reason="set LIGO_BENCH=1 to run the benchmark")
def test_bindings_answered_304(serve: Callable[..., Server], source: StaticSource) -> None:
    def handler(r: Request) -> Response:
        if r.headers.get("if-none-match"):
            return 304, {}, b""
        return 200, {"Content-Type": "application/json", "ETag": '"sha256:aa"'}, b'{"items":[]}'

    s = serve(handler)
    with Client(address=s.address, server_id=LIGO_ID, x509_source=source) as c:
        c.bindings()  # the first answer is 200 and fills the cache
        for _ in range(20):
            c.bindings()
        times = []
        for _ in range(CALLS):
            t = time.perf_counter()
            c.bindings()
            times.append((time.perf_counter() - t) * 1000)
    times.sort()
    median, p99 = statistics.median(times), times[int(len(times) * 0.99) - 1]
    print(f"\nbindings 304: median {median:.2f} ms, p99 {p99:.2f} ms over {CALLS} calls")
    assert median < MEDIAN_LIMIT_MS
