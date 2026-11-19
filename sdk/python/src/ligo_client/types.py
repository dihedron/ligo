"""The data the workload API returns, as frozen dataclasses with the Go SDK's fields in snake case."""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import LigoError


@dataclass(frozen=True)
class Auth:
    """Where the binding's credential is kept."""

    strategy: str = ""  # "vault-static", "vault-dynamic", or "svid" when the SVID is the credential
    store_type: str = ""
    store_instance: str = ""
    config: Mapping[str, str] = field(
        default_factory=dict
    )  # address, audience, authMount, role, secretPath or credsPath


@dataclass(frozen=True)
class Binding:
    """One binding of the calling workload."""

    id: str = ""
    name: str = ""
    source: str = ""
    target: str = ""
    access_level: str = ""
    platform_type: str = ""
    platform: str = ""
    revision: int = 0
    updated_at: dt.datetime | None = None
    spec: Mapping[str, Any] = field(default_factory=dict)  # differs per platform type
    auth: Auth = field(default_factory=Auth)
    description: str = ""  # what the binding is for; text, never interpreted
    annotations: Mapping[str, str] = field(default_factory=dict)  # operator-defined keys; a copy

    def endpoint(self) -> str:
        """The spec's "endpoint", or "" when the platform type has none."""
        e = self.spec.get("endpoint")
        return e if isinstance(e, str) else ""


@dataclass(frozen=True)
class PortRange:
    """Inclusive; a single port has low == high."""

    low: int
    high: int


@dataclass(frozen=True)
class Flow:
    """One network flow."""

    name: str = ""
    purpose: str = ""
    protocol: str = ""
    destination: str = ""
    ports: tuple[PortRange, ...] = ()
    tls: bool = False
    server_name: str = ""
    description: str = ""
    declared_by: str = ""


@dataclass(frozen=True)
class BindingFlows:
    """The network flows a binding needs."""

    binding: str = ""
    source: str = ""
    target: str = ""
    flows: tuple[Flow, ...] = ()


def _str(d: Mapping[str, Any], key: str) -> str:
    v = d.get(key, "")
    if v is None:
        return ""
    if not isinstance(v, str):
        raise LigoError(f"the answer is not a bindings document: {key} is not a string")
    return v


def _map(d: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    v = d.get(key)
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise LigoError(f"the answer is not a bindings document: {key} is not an object")
    return v


def _list(d: Mapping[str, Any], key: str) -> list[Any]:
    v = d.get(key)
    if v is None:
        return []
    if not isinstance(v, list):
        raise LigoError(f"the answer is not a flows document: {key} is not a list")
    return v


def _port(p: object) -> PortRange:
    """A port as ligo writes it: a number, or "low-high"."""
    if isinstance(p, int) and not isinstance(p, bool):
        return PortRange(p, p)
    if isinstance(p, str):
        low, sep, high = p.partition("-")
        if sep and low.isdigit() and high.isdigit():
            return PortRange(int(low), int(high))
    raise LigoError(f'the answer is not a flows document: port {p!r}: a number or "low-high"')


def binding_from_json(d: Any) -> Binding:
    if not isinstance(d, dict):
        raise LigoError("the answer is not a bindings document: an item is not an object")
    auth = _map(d, "auth")
    config = _map(auth, "config")
    updated = d.get("updatedAt")
    try:
        when = dt.datetime.fromisoformat(updated.replace("Z", "+00:00")) if isinstance(updated, str) else None
    except ValueError as e:
        raise LigoError(f"the answer is not a bindings document: {e}") from None
    revision = d.get("revision")
    if revision is None:
        revision = 0
    if isinstance(revision, bool) or not isinstance(revision, int):
        raise LigoError("the answer is not a bindings document: revision is not an integer")
    ann = _map(d, "annotations")
    return Binding(
        id=_str(d, "id"),
        name=_str(d, "name"),
        source=_str(d, "source"),
        target=_str(d, "target"),
        access_level=_str(d, "accessLevel"),
        platform_type=_str(d, "platformType"),
        platform=_str(d, "platform"),
        revision=revision,
        updated_at=when,
        spec=dict(_map(d, "spec")),
        auth=Auth(
            strategy=_str(auth, "secretStorageStrategy"),
            store_type=_str(auth, "secretStoreType"),
            store_instance=_str(auth, "secretStoreInstance"),
            config={
                k: v if isinstance(v, str) else str(v) for k, v in config.items()
            },  # the store plugins write strings
        ),
        description=_str(d, "description"),
        annotations={k: v for k, v in ann.items() if isinstance(v, str)},
    )


def flows_from_json(d: Any) -> BindingFlows:
    if not isinstance(d, dict):
        raise LigoError("the answer is not a flows document: an item is not an object")
    flows = []
    for f in _list(d, "flows"):
        if not isinstance(f, dict):
            raise LigoError("the answer is not a flows document: a flow is not an object")
        flows.append(
            Flow(
                name=_str(f, "name"),
                purpose=_str(f, "purpose"),
                protocol=_str(f, "protocol"),
                destination=_str(f, "destination"),
                ports=tuple(_port(p) for p in _list(f, "ports")),
                tls=bool(f.get("tls")),
                server_name=_str(f, "serverName"),
                description=_str(f, "description"),
                declared_by=_str(f, "declaredBy"),
            )
        )
    return BindingFlows(
        binding=_str(d, "binding"), source=_str(d, "source"), target=_str(d, "target"), flows=tuple(flows)
    )
