# SPDX-License-Identifier: MIT
"""PY-G: the documents of api/testdata/workload decode to the values the Go SDK's test expects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ligo_client import store
from ligo_client.types import binding_from_json, flows_from_json

DIR = Path(__file__).resolve().parents[3] / "api" / "testdata" / "workload"


def load(name: str) -> Any:
    return json.loads((DIR / name).read_text())


def test_bindings_and_flows_equal_the_expected_values() -> None:
    want = load("expected.json")
    bindings = [
        {
            "id": b.id, "name": b.name, "source": b.source, "target": b.target, "accessLevel": b.access_level,
            "platformType": b.platform_type, "platform": b.platform, "revision": b.revision,
            "updatedAt": int(b.updated_at.timestamp()) if b.updated_at else 0, "description": b.description,
            "annotations": dict(b.annotations), "endpoint": b.endpoint(),
            "auth": {"strategy": b.auth.strategy, "storeType": b.auth.store_type,
                     "storeInstance": b.auth.store_instance, "config": dict(b.auth.config)},
        }
        for b in map(binding_from_json, load("bindings.json")["items"])
    ]  # fmt: skip
    assert bindings == want["bindings"]
    flows = [
        {
            "binding": bf.binding, "source": bf.source, "target": bf.target,
            "flows": [
                {"name": f.name, "purpose": f.purpose, "protocol": f.protocol, "destination": f.destination,
                 "ports": [[p.low, p.high] for p in f.ports], "tls": f.tls, "serverName": f.server_name,
                 "description": f.description, "declaredBy": f.declared_by}
                for f in bf.flows
            ],
        }
        for bf in map(flows_from_json, load("flows.json")["items"])
    ]  # fmt: skip
    assert flows == want["flows"]


def test_store_documents_equal_the_expected_values() -> None:
    want = load("expected.json")
    token, ttl = store.parse_login((DIR / "store-login.json").read_bytes())
    assert {"token": token, "ttlSeconds": ttl} == want["login"]
    now = 1_800_000_000.0
    for name, strategy in (("static", store.STATIC), ("dynamic", store.DYNAMIC)):
        c = store.parse_secret(strategy, (DIR / f"store-{name}.json").read_bytes(), now)
        lease = int(c.expires.timestamp() - now) if c.expires else 0
        assert {"username": c.username, "password": c.password, "leaseSeconds": lease} == want[name]
