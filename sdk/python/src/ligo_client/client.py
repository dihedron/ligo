# SPDX-License-Identifier: MIT
"""The client of ligo's workload API (.specs/ligo-client-sdk-python.md §3)."""

from __future__ import annotations

import logging
import ssl
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Any

from spiffe import SpiffeId

from . import _rest, _tls, flowcheck, store
from .errors import (
    LigoError,
    NoCredential,
    StoreError,
    StoreNotAllowed,
    Unauthorized,
    Unavailable,
    UnsupportedStrategy,
)
from .types import Binding, BindingFlows, binding_from_json, flows_from_json
from .watch import MAX_BACKOFF, Event, EventKind, jitter

MIN_POLL = 5.0  # T-C6
DEFAULT_POLL = 30.0


@dataclass
class _Cached:
    etag: str
    items: list[Any]


class Client:
    """Reads the calling workload's bindings. It is thread-safe and a context manager.

    The constructor validates and does not call ligo. The default sources (spiffe.X509Source on
    SPIFFE_ENDPOINT_SOCKET) are opened on first use and closed by close(); sources the caller gives
    are the caller's to close.
    """

    def __init__(
        self,
        address: str,
        server_id: str,
        *,
        x509_source: _tls.X509Source | None = None,
        jwt_source: Any = None,
        store_roots: str | None = None,
        allowed_stores: Sequence[str] = (),
        poll_interval: float = DEFAULT_POLL,
        logger: logging.Logger | None = None,
    ) -> None:
        host, sep, port = address.rpartition(":")
        if not sep or not host or not port.isdigit() or int(port) > 65535 or "/" in address:
            raise ValueError(f"address {address!r}: host:port is required, with no scheme")
        try:
            self._server = SpiffeId(server_id)
        except Exception as e:
            raise ValueError(f"server_id: {e}") from None
        if poll_interval < MIN_POLL:
            raise ValueError(f"poll_interval {poll_interval}: at least {MIN_POLL} seconds")
        self._host, self._port, self._server_id = host.strip("[]"), int(port), server_id
        self._poll = poll_interval
        self._log = logger or logging.getLogger("ligo_client")
        self._store_ctx = store.tls_context(store_roots)
        try:
            self._allowed_stores = frozenset(store.store_address(a) for a in allowed_stores)
        except ValueError as e:
            raise ValueError(f"allowed_stores: {e}") from None
        self._jwt_source, self._owns_jwt = jwt_source, False
        self._now = time.time  # the clock of the token cache and of leases; the tests replace it
        self._tokens: dict[tuple[str, str, str, str], tuple[str, float]] = {}  # until: 80 % of the TTL

        self._lock = threading.Lock()
        self._source = x509_source
        self._owns_source = False
        self._context: ssl.SSLContext | None = None
        self._fingerprint: tuple[bytes, ...] = ()
        self._bindings: dict[tuple[str, str], _Cached] = {}
        self._flows: dict[str, _Cached] = {}
        self._closed = False
        self._closing = threading.Event()  # set by close(): ends every watch

    # -- lifecycle

    def __enter__(self) -> Client:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()

    def close(self) -> None:
        """Drops what the client remembers and closes the sources it opened."""
        self._closing.set()
        with self._lock:
            self._closed = True
            self._bindings.clear()
            self._flows.clear()
            self._tokens.clear()  # T-C4
            self._context = None
            source, owned = self._source, self._owns_source
            self._source = None if owned else source
            jwt, owns_jwt = self._jwt_source, self._owns_jwt
            self._jwt_source = None if owns_jwt else jwt
        for opened, was_owned in ((source, owned), (jwt, owns_jwt)):
            if was_owned and opened is not None and hasattr(opened, "close"):
                opened.close()

    # -- operations

    def bindings(self, target: str | None = None, platform_type: str | None = None) -> list[Binding]:
        """The workload's bindings. A not-modified answer returns the remembered list; none is not an error."""
        query = {k: v for k, v in (("target", target), ("platformType", platform_type)) if v}
        items = self._get("/v1/bindings", query, self._bindings, (target or "", platform_type or ""))
        return [binding_from_json(i) for i in items]

    def flows(self, target: str | None = None) -> list[BindingFlows]:
        """The network flows of the workload's bindings. Data only."""
        items = self._get("/v1/flows", {"target": target} if target else {}, self._flows, target or "")
        return [flows_from_json(i) for i in items]

    def credential(self, binding: Binding) -> store.Credential:
        """Reads the binding's credential from its secret store, logging in with a JWT-SVID.

        Every call reads the store: with vault-dynamic each read makes a new credential, so read once
        and follow watch().
        """
        try:
            return self._credential(binding)
        except (NoCredential, UnsupportedStrategy, StoreNotAllowed, StoreError, Unauthorized) as e:
            raise type(e)(f"the credential of binding {binding.name}: {e}") from None

    def invalidate(self, binding: Binding) -> None:
        """Forgets the store login of the binding: call it when the target refuses the credential."""
        try:
            address = store.store_address(binding.auth.config.get("address", ""))
        except ValueError:
            return
        cfg = binding.auth.config
        with self._lock:
            self._tokens.pop((address, cfg.get("namespace", ""), cfg.get("authMount", ""), cfg.get("role", "")), None)

    def check_flows(self, target: str | None = None, **options: Any) -> flowcheck.FlowResults:
        """Reads the flows of the bindings and tests them (see flowcheck.check_flow_data for the options).

        The defaults come from what the client knows: a flow declared by ligo is verified as an X509-SVID
        against the client's own bundle, and a flow of a PostgreSQL binding that a target or a platform
        declares asks for TLS inside the protocol. It runs when called, never on its own.
        """
        flows = self.flows(target)
        platforms = {b.name: b.platform_type for b in self.bindings(target)}
        if "spiffe_bundle" not in options:
            with self._lock:
                source = self._source_locked()
            options["spiffe_bundle"] = source.get_bundle_for_trust_domain(self._server.trust_domain)
        options.setdefault("platforms", platforms)
        return flowcheck.check_flow_data(flows, **options)

    def check_flow_data(self, flows: Sequence[BindingFlows], **options: Any) -> flowcheck.FlowResults:
        """Tests flows obtained elsewhere; with the client's own bundle for the flows of ligo."""
        if "spiffe_bundle" not in options:
            with self._lock:
                source = self._source_locked()
            options["spiffe_bundle"] = source.get_bundle_for_trust_domain(self._server.trust_domain)
        return flowcheck.check_flow_data(flows, **options)

    def watch(
        self,
        target: str | None = None,
        platform_type: str | None = None,
        *,
        watch_credentials: bool = False,
        stop: threading.Event | None = None,
    ) -> Iterator[Event]:
        """Polls the bindings that match and yields an Event for every change; it blocks between polls.

        With watch_credentials it also reads the credential of each new or changed binding, and again at
        two thirds of a lease. A failed poll keeps the state and is tried again later, with a backoff up
        to five minutes and the server's Retry-After. The generator ends when it is closed, when close() is
        called on the client, or when `stop` is set.
        """
        known: dict[str, Binding] = {}
        due: dict[str, float] = {}  # when to read a binding's credential
        failures = 0
        next_poll = self._now()
        while not self._stopped(stop):
            now = self._now()
            if now >= next_poll:
                wait = jitter(self._poll)
                try:
                    items = self.bindings(target, platform_type)
                except LigoError as e:
                    wait = min(self._poll * 2 ** min(failures, 10), MAX_BACKOFF)
                    if isinstance(e, Unavailable) and e.retry_after:
                        wait = max(wait, e.retry_after)
                    failures += 1
                    self._log.warning("watch: poll failed, retry in %.0f s: %s", wait, e)
                except RuntimeError:
                    if self._closing.is_set():
                        return
                    raise
                else:
                    failures = 0
                    yield from self._diff(known, due, items, watch_credentials, now)
                next_poll = now + wait
            wake = next_poll
            for b in sorted(known.values(), key=lambda x: (x.name, x.id)):
                at = due.get(b.id)
                if at is None:
                    continue
                if at > now:
                    wake = min(wake, at)
                    continue
                try:
                    cred = self.credential(b)
                except NoCredential:
                    del due[b.id]
                except LigoError as e:
                    due[b.id] = next_poll
                    self._log.warning("watch: credential not read: binding %s, target %s: %s", b.name, b.target, e)
                else:
                    del due[b.id]
                    if cred.expires is not None:
                        due[b.id] = now + (cred.expires.timestamp() - now) * 2 / 3
                        wake = min(wake, due[b.id])
                    yield Event(EventKind.CREDENTIAL_ROTATED, binding=b, credential=cred)
            if self._sleep(max(0.0, wake - self._now()), stop):
                return

    def _stopped(self, stop: threading.Event | None) -> bool:
        return self._closing.is_set() or (stop is not None and stop.is_set())

    def _sleep(self, seconds: float, stop: threading.Event | None) -> bool:
        """Waits; True when the watch must end. The tests replace it."""
        if stop is None:
            return self._closing.wait(seconds)
        deadline = time.monotonic() + seconds
        while not self._stopped(stop):
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            self._closing.wait(min(left, 0.25))  # `stop` is another event: look at it often
        return True

    @staticmethod
    def _diff(
        known: dict[str, Binding], due: dict[str, float], items: list[Binding], credentials: bool, now: float
    ) -> Iterator[Event]:
        seen = set()
        for b in sorted(items, key=lambda x: (x.name, x.id)):
            seen.add(b.id)
            old = known.get(b.id)
            if old is not None and old.revision == b.revision:
                continue
            known[b.id] = b
            if credentials:
                due[b.id] = now
            if old is not None:
                yield Event(EventKind.CHANGED, binding=b, previous=old)
            else:
                yield Event(EventKind.ADDED, binding=b)
        for old in sorted(known.values(), key=lambda x: (x.name, x.id)):
            if old.id not in seen:
                del known[old.id]
                due.pop(old.id, None)
                yield Event(EventKind.REMOVED, previous=old)

    def connect(self, address: str, server_id: str, *, timeout: float = 15.0) -> ssl.SSLSocket:
        """An mTLS connection with the workload's SVID to a server that presents server_id only.

        The server's ID is checked before this returns, so nothing is sent to another server.
        """
        host, _, port = address.rpartition(":")
        sid = SpiffeId(server_id)
        return _tls.connect(self._ssl_context(sid.trust_domain), host.strip("[]"), int(port), server_id, timeout)

    # -- internals

    def _credential(self, b: Binding) -> store.Credential:
        cfg = b.auth.config
        strategy = b.auth.strategy
        if strategy in ("", store.NONE):
            raise NoCredential("the binding has no credential")
        if strategy not in (store.STATIC, store.DYNAMIC):
            raise UnsupportedStrategy(f"unsupported secret storage strategy {strategy!r}")
        path = cfg.get("credsPath", "") if strategy == store.DYNAMIC else cfg.get("secretPath", "")
        try:
            address = store.store_address(cfg.get("address", ""))
        except ValueError as e:
            raise StoreNotAllowed(f"store address not allowed: {e}") from None
        if self._allowed_stores and address not in self._allowed_stores:
            raise StoreNotAllowed(f"store address not allowed: {address} is not in allowed_stores")
        for k in ("audience", "authMount", "role"):
            if not cfg.get(k):
                raise StoreError(f"the binding names no {k}")
        if not path:
            raise StoreError("the binding names no path")
        key = (address, cfg.get("namespace", ""), cfg["authMount"], cfg["role"])
        token, fresh = self._store_token(b, key, cfg["audience"])
        try:
            body = store.call(self._store_ctx, address, "GET", path, token=token, namespace=key[1])
        except store.CallError as e:
            if e.status != 403 or fresh:
                raise StoreError(f"read: {e}") from None
            self._drop_token(key)  # the remembered token may be revoked: one new login
            token, _ = self._store_token(b, key, cfg["audience"])
            try:
                body = store.call(self._store_ctx, address, "GET", path, token=token, namespace=key[1])
            except store.CallError as e2:
                raise StoreError(f"read: {e2}") from None
        return store.parse_secret(strategy, body, self._now())

    def _drop_token(self, key: tuple[str, str, str, str]) -> None:
        with self._lock:
            self._tokens.pop(key, None)

    def _store_token(self, b: Binding, key: tuple[str, str, str, str], audience: str) -> tuple[str, bool]:
        """The remembered store token, or a login; the second result reports a new login."""
        with self._lock:
            have = self._tokens.get(key)
        if have is not None and self._now() < have[1]:
            return have[0], False
        address, namespace, mount, role = key
        jwt = self._jwt(audience)
        try:
            data = store.call(
                self._store_ctx,
                address,
                "POST",
                f"auth/{mount}/login",
                namespace=namespace,
                body={"role": role, "jwt": jwt},
            )
        except store.CallError as e:
            raise StoreError(f"login: {e}") from None
        try:
            value, ttl = store.parse_login(data)
        except StoreError as e:
            raise StoreError(f"login: {e}") from None
        self._log.debug("store login: binding %s, target %s, store %s", b.name, b.target, address)
        with self._lock:
            self._tokens[key] = (value, self._now() + ttl * 0.8)
        return value, True

    def _jwt(self, audience: str) -> str:
        """A JWT-SVID for the audience, with the identity of the X.509-SVID that fetched the bindings."""
        with self._lock:
            if self._jwt_source is None:
                from spiffe import JwtSource

                self._jwt_source, self._owns_jwt = JwtSource(), True
            jwt_source = self._jwt_source
            source = self._source_locked()
        try:
            svid = jwt_source.fetch_svid({audience}, source.svid.spiffe_id)
            token = svid.token
        except Exception as e:  # the agent's errors may carry anything
            raise Unauthorized(f"no JWT-SVID could be fetched: {type(e).__name__}") from None
        if not isinstance(token, str) or not token:
            raise Unauthorized("no JWT-SVID could be fetched")
        return token

    def _get(self, path: str, query: dict[str, str], cache: dict[Any, _Cached], key: Any) -> list[Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("the client is closed")
            cached = cache.get(key)
        items, etag, not_modified = _rest.get(
            lambda: self._ssl_context(self._server.trust_domain),
            self._host,
            self._port,
            self._server_id,
            path,
            query,
            cached.etag if cached else "",
        )
        if not_modified and cached is not None:
            return cached.items
        with self._lock:
            cache[key] = _Cached(etag, items)
        return items

    def _source_locked(self) -> Any:
        """The X.509 source; the caller holds the lock. The default one is opened on first use."""
        if self._source is None:
            from spiffe import X509Source

            self._source = X509Source()  # the Workload API at SPIFFE_ENDPOINT_SOCKET
            self._owns_source = True
        return self._source

    def _ssl_context(self, trust_domain: Any) -> ssl.SSLContext:
        with self._lock:
            source = self._source_locked()
            now = _tls.current_fingerprint(source, trust_domain)
            if self._context is None or now != self._fingerprint:
                self._context, self._fingerprint = _tls.build_context(source, trust_domain)
            return self._context
