#!/opt/ligo-py/bin/python
"""The lab's echo client in Python (lab only, not hardened; .specs/ligo-client-sdk-python.md PY-L1).

The same as test/lab/echo/client, on ligo-client: it finds its binding to an echo target, authenticates
as the binding says (its SVID, or the password OpenBao keeps for it) and prints what the server echoes.
Exit codes: 0 echoed, 1 error, 2 no binding, 3 denied. REST only: the Python SDK has no gRPC.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import TextIO

import ligo_client

EXIT_ECHOED, EXIT_ERROR, EXIT_NO_BINDING, EXIT_DENIED = 0, 1, 2, 3


def echo(client: ligo_client.Client, endpoint: str, server_id: str, mode: str, user: str, password: str, message: str) -> str:
    if mode not in ("svid", "password"):
        raise ValueError(f"mode {mode!r}: svid or password")
    lines = message + "\n"
    if mode == "password":
        lines = f"auth {user} {password}\n" + lines
    with client.connect(endpoint, server_id, timeout=15) as sock:
        sock.sendall(lines.encode())
        answer = sock.makefile("rb").readline().decode()
    return answer.removesuffix("\n")


def run(args: list[str], out: TextIO) -> int:
    p = argparse.ArgumentParser(prog="echo-client-py")
    p.add_argument("--target", default="")
    p.add_argument("--message", default="hello")
    p.add_argument("--ligo", default="ligo1.ligo.lab:8443")
    p.add_argument("--ligo-id", default="spiffe://prod.lab/ns/sys/sa/ligo")
    p.add_argument("--transport", default="rest", choices=["rest"])
    p.add_argument("--direct", default="")
    p.add_argument("--mode", default="svid")
    p.add_argument("--user", default="")
    p.add_argument("--password", default="")
    p.add_argument("--server-id", default="spiffe://prod.lab/ns/lab/sa/echo-server")
    try:
        a = p.parse_args(args)
    except SystemExit:
        return EXIT_ERROR

    def fail(msg: str) -> int:
        print(f"error: {msg}", file=out)
        return EXIT_ERROR

    if "\n" in a.message or "\t" in a.message:
        return fail("--message: one line without tabs")
    os.environ.setdefault("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/prod/agent.sock")
    with ligo_client.Client(a.ligo, a.ligo_id, store_roots=os.environ.get("ECHO_CA_FILE", "/etc/ligo-lab/ca.crt")) as client:
        endpoint, server_id, mode, user, password = a.direct, a.server_id, a.mode, a.user, a.password
        if not a.direct:
            if not a.target:
                return fail("--target or --direct is required")
            try:
                bindings = client.bindings(target=a.target)
            except ligo_client.LigoError as e:
                return fail(f"ligo's workload API: {e}")
            if not bindings:
                print("no binding", file=out)
                return EXIT_NO_BINDING
            b = bindings[0]
            endpoint = b.endpoint()
            server_id = str(b.spec.get("serverId", ""))
            mode = str(b.spec.get("mode", ""))
            try:
                cred = client.credential(b)
                user, password = cred.username, cred.password
            except ligo_client.NoCredential:
                if mode == "password":
                    return fail("the binding's password: no credential")
            except ligo_client.LigoError as e:
                return fail(f"the binding's password: {e}")
            print(f"binding {b.name}: {mode} mode, {endpoint}", file=out)
        try:
            answer = echo(client, endpoint, server_id, mode, user, password, a.message)
        except (OSError, ValueError, ligo_client.LigoError) as e:
            return fail(f"the echo server: {e}")
    print(answer, file=out)
    if answer == "denied":
        return EXIT_DENIED
    if answer.startswith(a.message + "\t"):
        return EXIT_ECHOED
    return fail("unexpected answer")


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:], sys.stdout))
