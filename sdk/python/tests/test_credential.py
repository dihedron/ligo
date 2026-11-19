# SPDX-License-Identifier: MIT
"""PY-6 to PY-10 and PY-15 (.specs/ligo-client-sdk-python.md §6)."""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
import pickle
from collections.abc import Callable
from typing import Any

import pytest

from ligo_client import (
    Auth,
    Binding,
    Client,
    NoCredential,
    StoreError,
    StoreNotAllowed,
    Unauthorized,
    UnsupportedStrategy,
)

from .conftest import LIGO_ID, WORKER_ID, FakeJwt, StaticSource, StoreRequest, StoreResponse, StoreServer

PASSWORD = "s3cr3t-Passw0rd"
TOKEN = "hvs.store-token"

Maker = Callable[..., StoreServer]


def login(token: str = TOKEN, ttl: int = 100) -> StoreResponse:
    return 200, {}, json.dumps({"auth": {"client_token": token, "lease_duration": ttl}}).encode()


def kv(user: str = "svc_ledger") -> StoreResponse:
    body = {"data": {"data": {"username": user, "password": PASSWORD}, "metadata": {"version": 3}}}
    return 200, {}, json.dumps(body).encode()


def dynamic(lease: int = 90) -> StoreResponse:
    body = {"lease_duration": lease, "data": {"username": "v-user-1", "password": PASSWORD}}
    return 200, {}, json.dumps(body).encode()


def binding(url: str, strategy: str = "vault-static", **config: str) -> Binding:
    cfg = {
        "address": url,
        "audience": "https://vault.lab",
        "authMount": "jwt",
        "role": "binding-0192",
        "secretPath": "kv/data/bindings/0192",
        "credsPath": "database/creds/binding-0192",
    }
    cfg.update(config)
    cfg = {k: v for k, v in cfg.items() if v != ""}
    return Binding(
        id="0192",
        name="workers-ledger",
        target="ledger",
        auth=Auth(strategy=strategy, store_type="vault", store_instance="vault-prod", config=cfg),
    )


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


def make_client(
    source: StaticSource, jwt: FakeJwt, ca_file: str | None, clock: Clock | None = None, **kw: Any
) -> Client:
    c = Client(address="127.0.0.1:1", server_id=LIGO_ID, x509_source=source, jwt_source=jwt, store_roots=ca_file, **kw)
    if clock is not None:
        c._now = clock  # the clock of the token cache and of the lease
    return c


def routes(
    login_resp: Callable[[], StoreResponse] = login, read: Callable[[], StoreResponse] = kv
) -> Callable[[StoreRequest], StoreResponse]:
    def handler(r: StoreRequest) -> StoreResponse:
        if r.method == "POST" and r.path.endswith("/login"):
            return login_resp()
        return read()

    return handler


# PY-6
def test_vault_static(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes())
    jwt = FakeJwt()
    with make_client(source, jwt, ca_file) as c:
        cred = c.credential(binding(s.url))
    assert (cred.username, cred.password, cred.expires) == ("svc_ledger", PASSWORD, None)
    login_req, read_req = s.requests
    assert (login_req.method, login_req.path) == ("POST", "/v1/auth/jwt/login")
    assert login_req.json() == {"role": "binding-0192", "jwt": "jwt-for-https://vault.lab"}
    assert (read_req.method, read_req.path) == ("GET", "/v1/kv/data/bindings/0192")
    assert read_req.headers["x-vault-token"] == TOKEN
    assert jwt.calls == [({"https://vault.lab"}, WORKER_ID)]  # the identity of the X.509-SVID


# PY-7
def test_vault_dynamic(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes(read=dynamic))
    clock = Clock()
    with make_client(source, FakeJwt(), ca_file, clock) as c:
        cred = c.credential(binding(s.url, "vault-dynamic"))
    assert s.requests[1].path == "/v1/database/creds/binding-0192"
    assert (cred.username, cred.password) == ("v-user-1", PASSWORD)
    assert cred.expires is not None and cred.expires.timestamp() == clock.t + 90


@pytest.mark.parametrize("lease", [0, -5, 10**12])
def test_dynamic_lease_out_of_range(lease: int, store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes(read=lambda: dynamic(lease)))
    with make_client(source, FakeJwt(), ca_file) as c, pytest.raises(StoreError):
        c.credential(binding(s.url, "vault-dynamic"))


# PY-8
def test_token_reuse_expiry_and_invalidate(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes())
    clock = Clock()
    b = binding(s.url)

    def logins() -> int:
        return sum(r.path.endswith("/login") for r in s.requests)

    with make_client(source, FakeJwt(), ca_file, clock) as c:
        c.credential(b)
        c.credential(b)
        assert logins() == 1  # the token is reused
        clock.t += 79
        c.credential(b)
        assert logins() == 1  # 80 % of 100 s is not over
        clock.t += 2
        c.credential(b)
        assert logins() == 2  # over
        c.invalidate(b)
        c.credential(b)
        assert logins() == 3


def test_403_on_a_remembered_token_logs_in_once_more(store: Maker, source: StaticSource, ca_file: str) -> None:
    reads = []

    def read() -> StoreResponse:
        reads.append(1)
        return (403, {}, b"permission denied") if len(reads) == 2 else kv()

    s = store(routes(read=read))
    with make_client(source, FakeJwt(), ca_file) as c:
        b = binding(s.url)
        c.credential(b)  # login 1, read 1
        c.credential(b)  # remembered token, read 2 is a 403, login 2, read 3
    paths = [(r.method, r.path.rsplit("/", 1)[-1]) for r in s.requests]
    assert paths == [("POST", "login"), ("GET", "0192"), ("GET", "0192"), ("POST", "login"), ("GET", "0192")]


def test_403_on_a_fresh_token_is_final(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes(read=lambda: (403, {}, b"permission denied " + PASSWORD.encode())))
    with make_client(source, FakeJwt(), ca_file) as c, pytest.raises(StoreError) as e:
        c.credential(binding(s.url))
    assert len(s.requests) == 2 and "403" in str(e.value) and PASSWORD not in str(e.value)


# PY-9
@pytest.mark.parametrize("strategy", ["svid", ""])
def test_no_credential(strategy: str, source: StaticSource) -> None:
    with make_client(source, FakeJwt(), None) as c, pytest.raises(NoCredential):
        c.credential(binding("https://vault.lab:8200", strategy))


def test_unsupported_strategy(source: StaticSource) -> None:
    with make_client(source, FakeJwt(), None) as c, pytest.raises(UnsupportedStrategy, match="vault-magic"):
        c.credential(binding("https://vault.lab:8200", "vault-magic"))


@pytest.mark.parametrize(
    "address",
    [
        "http://vault.lab:8200",
        "vault.lab:8200",
        "https://u:p@vault.lab",
        "https://vault.lab/x",
        "https://vault.lab/?q=1",
    ],
)
def test_store_address_must_be_https_host_port(address: str, source: StaticSource) -> None:
    with make_client(source, FakeJwt(), None) as c, pytest.raises(StoreNotAllowed):
        c.credential(binding(address))


def test_allowed_stores(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes())
    jwt = FakeJwt()
    with (
        make_client(source, jwt, ca_file, allowed_stores=["https://other.lab:8200"]) as c,
        pytest.raises(StoreNotAllowed),
    ):
        c.credential(binding(s.url))
    assert s.requests == [] and jwt.calls == []  # no JWT-SVID goes to a store that is not allowed
    with make_client(source, jwt, ca_file, allowed_stores=[s.url]) as c:
        assert c.credential(binding(s.url)).username == "svc_ledger"


def test_allowed_stores_are_validated(source: StaticSource) -> None:
    with pytest.raises(ValueError, match="allowed_stores"):
        make_client(source, FakeJwt(), None, allowed_stores=["http://vault.lab"])


def test_store_certificate_outside_store_roots(store: Maker, source: StaticSource, ca_file: str) -> None:
    from .conftest import CA

    s = store(routes(), CA())  # signed by another CA
    with make_client(source, FakeJwt(), ca_file) as c, pytest.raises(StoreError):
        c.credential(binding(s.url))
    assert s.requests == []


@pytest.mark.parametrize("missing", ["address", "audience", "authMount", "role", "secretPath"])
def test_binding_that_does_not_say_how(missing: str, source: StaticSource) -> None:
    b = binding("https://vault.lab:8200", **{missing: ""})
    with make_client(source, FakeJwt(), None) as c, pytest.raises((StoreError, StoreNotAllowed)):
        c.credential(b)


def test_a_redirect_is_not_followed(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(lambda r: (307, {"Location": "https://elsewhere.example/"}, b""))
    with make_client(source, FakeJwt(), ca_file) as c, pytest.raises(StoreError):
        c.credential(binding(s.url))
    assert len(s.requests) == 1  # the JWT-SVID went to the store and nowhere else


def test_store_body_over_the_limit(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(lambda r: (200, {}, b" " * ((8 << 20) + 1)))
    with make_client(source, FakeJwt(), ca_file) as c, pytest.raises(StoreError):
        c.credential(binding(s.url))


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"{}",
        b"[]",
        b'{"auth":{}}',
        b'{"auth":{"client_token":""}}',
        b'{"auth":{"client_token":"t","lease_duration":-1}}',
    ],
)
def test_bad_login_answers(body: bytes, store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes(login_resp=lambda: (200, {}, body)))
    with make_client(source, FakeJwt(), ca_file) as c, pytest.raises(StoreError):
        c.credential(binding(s.url))


@pytest.mark.parametrize(
    "body", [b"", b"{}", b'{"data":{"data":{"username":"u"}}}', b'{"data":{"data":{"password":"p"}}}']
)
def test_bad_secrets(body: bytes, store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes(read=lambda: (200, {}, body)))
    with make_client(source, FakeJwt(), ca_file) as c, pytest.raises(StoreError):
        c.credential(binding(s.url))


def test_the_jwt_source_failing_is_unauthorized(store: Maker, source: StaticSource, ca_file: str) -> None:
    class Broken(FakeJwt):
        def fetch_svid(self, audience: set[str], subject: Any = None, timeout: float | None = None) -> Any:
            raise RuntimeError("the agent is gone: " + PASSWORD)

    s = store(routes())
    with make_client(source, Broken(), ca_file) as c, pytest.raises(Unauthorized) as e:
        c.credential(binding(s.url))
    assert PASSWORD not in str(e.value) and s.requests == []


# PY-15
def test_namespace_goes_on_the_login_and_the_read(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes())
    with make_client(source, FakeJwt(), ca_file) as c:
        c.credential(binding(s.url, namespace="team-a"))
    assert [r.headers.get("x-vault-namespace") for r in s.requests] == ["team-a", "team-a"]
    s2 = store(routes())
    with make_client(source, FakeJwt(), ca_file) as c:
        c.credential(binding(s2.url))
    assert all("x-vault-namespace" not in r.headers for r in s2.requests)


# PY-10
def test_no_secret_is_printed_logged_copied_or_pickled(
    store: Maker, source: StaticSource, ca_file: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    s = store(routes())
    jwt = FakeJwt()
    with make_client(source, jwt, ca_file) as c:
        cred = c.credential(binding(s.url))
    shown = [
        repr(cred),
        str(cred),
        f"{cred}",
        f"{cred!r}",
        format(cred, ">40"),
        "%s %r" % (cred, cred),  # noqa: UP031
        repr(copy.copy(cred)),
        repr(copy.deepcopy(cred)),
        repr([cred]),
        repr({"c": cred}),
        str(dataclasses.replace(cred)),
    ]
    for text in shown:
        assert PASSWORD not in text, text
    assert "svc_ledger" in repr(cred)  # the user name is not secret
    logging.getLogger("ligo_client").info("credential %s", cred)
    for rec in caplog.records:
        text = rec.getMessage()
        assert PASSWORD not in text and TOKEN not in text and "jwt-for-" not in text, text
    assert PASSWORD not in caplog.text and TOKEN not in caplog.text
    with pytest.raises(TypeError):
        pickle.dumps(cred)


def test_errors_never_hold_a_body_a_token_or_a_jwt(store: Maker, source: StaticSource, ca_file: str) -> None:
    leak = f"{PASSWORD} {TOKEN} jwt-for-https://vault.lab"
    handlers: list[Callable[[StoreRequest], StoreResponse]] = [
        lambda r: (500, {}, leak.encode()),
        lambda r: (200, {}, leak.encode()),
    ]
    for handler in handlers:
        s = store(handler)
        with make_client(source, FakeJwt(), ca_file) as c, pytest.raises(StoreError) as e:
            c.credential(binding(s.url))
        text = f"{e.value!s} {e.value!r} {e.value.args}"
        assert PASSWORD not in text and TOKEN not in text and "jwt-for-" not in text


def test_close_forgets_the_tokens_and_closes_what_it_opened(store: Maker, source: StaticSource, ca_file: str) -> None:
    s = store(routes())
    jwt = FakeJwt()
    c = make_client(source, jwt, ca_file)
    c.credential(binding(s.url))
    c.close()
    assert not jwt.closed  # the caller's source is the caller's to close
    assert not c._tokens
