"""Fuzzing the decoders: whatever a server or a store sends, the SDK raises its own errors or none."""

from __future__ import annotations

import contextlib
import json
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from ligo_client import LigoError
from ligo_client.store import DYNAMIC, STATIC, parse_login, parse_secret
from ligo_client.types import binding_from_json, flows_from_json

JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=6),
    max_leaves=25,
)

# documents that look like the real ones, with the wrong types sprinkled in
KEYS = [
    "id",
    "name",
    "source",
    "target",
    "accessLevel",
    "platformType",
    "platform",
    "revision",
    "updatedAt",
    "spec",
    "auth",
    "description",
    "annotations",
    "flows",
    "ports",
    "tls",
    "config",
    "secretStorageStrategy",
]
LIKE = st.dictionaries(st.sampled_from(KEYS), JSON, max_size=10)


@settings(max_examples=300, deadline=None)
@given(LIKE | JSON)
def test_binding_decoder_raises_only_ligo_errors(doc: Any) -> None:
    try:
        b = binding_from_json(doc)
    except LigoError:
        return
    assert isinstance(b.description, str) and all(isinstance(v, str) for v in b.annotations.values())
    assert all(isinstance(v, str) for v in b.auth.config.values())


@settings(max_examples=300, deadline=None)
@given(LIKE | JSON)
def test_flows_decoder_raises_only_ligo_errors(doc: Any) -> None:
    try:
        bf = flows_from_json(doc)
    except LigoError:
        return
    for f in bf.flows:
        assert all(isinstance(p.low, int) and isinstance(p.high, int) for p in f.ports)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=200) | JSON.map(lambda d: json.dumps(d).encode()))
def test_store_answers_raise_only_ligo_errors(data: bytes) -> None:
    for call in (parse_login, lambda d: parse_secret(STATIC, d, 0.0), lambda d: parse_secret(DYNAMIC, d, 0.0)):
        with contextlib.suppress(LigoError):
            call(data)


@settings(max_examples=200, deadline=None)
@given(st.text(min_size=1), st.text(min_size=1), st.integers(min_value=1, max_value=10**6))
def test_valid_secrets_round_trip(user: str, password: str, lease: int) -> None:
    kv = json.dumps({"data": {"data": {"username": user, "password": password}}}).encode()
    cred = parse_secret(STATIC, kv, 0.0)
    assert (cred.username, cred.password, cred.expires) == (user, password, None)
    dyn = json.dumps({"lease_duration": lease, "data": {"username": user, "password": password}}).encode()
    got = parse_secret(DYNAMIC, dyn, 100.0)
    assert got.expires is not None and got.expires.timestamp() == 100.0 + lease
