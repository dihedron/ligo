"""What the Go lab tests ask of the Python SDK (.specs/ligo-client-sdk-python.md PY-L2, PY-L3).

Runs on ligo1 under the workload's user, in the venv of lab.sh (python.sh). The Go tests
(TestServeClientSDKPython, TestServeClientFlowcheckPython) file and approve the bindings, call this
helper and judge its JSON lines. The workload's SVID and JWT-SVID were minted by lab.sh into
LIGO_E2E_DIR, so this client reads them from files instead of the Workload API.

    sdk_check.py watch --target T         one JSON line per event, until the binding is removed
    sdk_check.py flowcheck --target T     {"results": [...]} for the flows of T
    sdk_check.py denied                   a flow to the cloud metadata address: it must be skipped
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import types
from pathlib import Path
from typing import Any

import ligo_client
from cryptography.hazmat.primitives.serialization import Encoding
from spiffe import TrustDomain, X509Bundle, X509Svid

LIGO_ID = "spiffe://prod.lab/ns/sys/sa/ligo"


class FileSource:
    """The SVID and bundle that lab.sh minted, as spiffe.X509Source gives them."""

    def __init__(self, directory: Path) -> None:
        self.svid = X509Svid.load(directory / "workload-svid.pem", directory / "workload-key.pem", Encoding.PEM)
        self._bundle = X509Bundle.load(TrustDomain("prod.lab"), directory / "workload-bundle.pem", Encoding.PEM)

    def get_bundle_for_trust_domain(self, trust_domain: Any) -> X509Bundle:
        return self._bundle


class FileJwt:
    """The JWT-SVID that lab.sh minted for the secrets backend, as spiffe.JwtSource gives it."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def fetch_svid(self, audience: set[str], subject: Any = None, timeout: float | None = None) -> Any:
        return types.SimpleNamespace(token=self._path.read_text().strip())


def make_client() -> ligo_client.Client:
    directory = Path(os.environ["LIGO_E2E_DIR"])
    address = os.environ["LIGO_E2E_WORKLOAD"].removeprefix("https://")
    return ligo_client.Client(
        address, LIGO_ID, x509_source=FileSource(directory), jwt_source=FileJwt(directory / "workload-store-jwt"),
        store_roots=os.environ["LIGO_TEST_CA"], poll_interval=5.0,
    )  # fmt: skip


def emit(**doc: Any) -> None:
    print(json.dumps(doc), flush=True)


def binding_doc(b: ligo_client.Binding | None) -> dict[str, Any] | None:
    if b is None:
        return None
    return {"name": b.name, "target": b.target, "strategy": b.auth.strategy, "endpoint": b.endpoint(),
            "description": b.description, "annotations": dict(b.annotations)}  # fmt: skip


def credential_doc(c: ligo_client.Credential | None) -> dict[str, Any] | None:
    if c is None:
        return None
    return {"username": c.username, "password": c.password, "expires": c.expires.timestamp() if c.expires else 0}


def watch(client: ligo_client.Client, target: str) -> None:
    rotated = 0
    for ev in client.watch(target=target, watch_credentials=True):
        emit(kind=ev.kind.value, binding=binding_doc(ev.binding), previous=binding_doc(ev.previous),
             credential=credential_doc(ev.credential))  # fmt: skip
        if ev.kind is ligo_client.EventKind.CREDENTIAL_ROTATED and rotated == 0 and ev.binding is not None:
            rotated = 1
            emit(kind="second_credential", credential=credential_doc(client.credential(ev.binding)))
            flows = client.flows(target=target)
            emit(kind="flows", bindings=len(flows), flows=sum(len(bf.flows) for bf in flows))
        if ev.kind is ligo_client.EventKind.REMOVED and ev.previous is not None:
            client.invalidate(ev.previous)
            try:
                client.credential(ev.previous)
                emit(kind="refused", error="")
            except ligo_client.StoreError as e:
                emit(kind="refused", error=type(e).__name__)
            emit(kind="bindings_after", count=len(client.bindings(target=target)))
            return


def result_doc(r: ligo_client.FlowResult) -> dict[str, Any]:
    return {"binding": r.binding, "target": r.target, "flow": r.flow, "destination": r.destination, "port": r.port,
            "protocol": r.protocol, "status": r.status.value, "reason": r.reason,
            "error": type(r.error).__name__ if r.error else ""}  # fmt: skip


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["watch", "flowcheck", "denied"])
    p.add_argument("--target", default="")
    a = p.parse_args()
    with make_client() as client:
        if a.command == "watch":
            watch(client, a.target)
        elif a.command == "flowcheck":
            results = client.check_flows(target=a.target, roots=os.environ["LIGO_TEST_CA"], timeout=5.0, retries=1)
            emit(results=[result_doc(r) for r in results])
        else:
            flows = [ligo_client.BindingFlows(binding="b", target="t", flows=(ligo_client.Flow(
                name="metadata", protocol="TCP", destination="169.254.169.254", ports=(ligo_client.PortRange(80, 80),)),))]
            emit(results=[result_doc(r) for r in ligo_client.check_flow_data(flows)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
