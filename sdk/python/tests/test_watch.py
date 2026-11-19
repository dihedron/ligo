# SPDX-License-Identifier: MIT
"""PY-11 and PY-12: watch (.specs/ligo-client-sdk-python.md §6)."""

from __future__ import annotations

import datetime as dt
import logging
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from ligo_client import (
    Binding,
    Client,
    Credential,
    EventKind,
    NoCredential,
    StoreError,
    Unavailable,
)

from .conftest import LIGO_ID, StaticSource


def b(id: str, name: str, revision: int = 1) -> Binding:
    return Binding(id=id, name=name, revision=revision, target="t")


class Script:
    """A scripted server and clock: each poll takes the next answer; each sleep moves the clock."""

    def __init__(self, c: Client, polls: list[Any], stop: threading.Event) -> None:
        self.c, self.polls, self.stop = c, list(polls), stop
        self.now = 1_000_000.0
        self.sleeps: list[float] = []
        self.polled = 0
        c._now = lambda: self.now
        c.bindings = self.bindings  # type: ignore[method-assign]
        c._sleep = self.sleep  # type: ignore[method-assign]

    def bindings(self, target: str | None = None, platform_type: str | None = None) -> list[Binding]:
        self.polled += 1
        if not self.polls:
            self.stop.set()
            return []
        answer = self.polls.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if not self.polls:
            self.stop.set()  # the last answer: the watch ends at its next sleep
        out: list[Binding] = answer
        return out

    def sleep(self, seconds: float, stop: threading.Event | None) -> bool:
        self.sleeps.append(seconds)
        self.now += seconds
        return self.stop.is_set()


def run(
    source: StaticSource,
    polls: list[Any],
    *,
    credentials: Callable[[Binding], Credential] | None = None,
    watch_credentials: bool = False,
    poll_interval: float = 30.0,
) -> tuple[list[Any], Script]:
    stop = threading.Event()
    c = Client(address="x:1", server_id=LIGO_ID, x509_source=source, poll_interval=poll_interval)
    s = Script(c, polls, stop)
    if credentials is not None:
        c.credential = credentials  # type: ignore[method-assign]
    events = list(c.watch(watch_credentials=watch_credentials, stop=stop))
    return events, s


def cred(lease: float | None, now: float = 1_000_000.0) -> Credential:
    exp = None if lease is None else dt.datetime.fromtimestamp(now + lease, dt.timezone.utc)
    return Credential("u", "p", exp)


# PY-11
def test_added_changed_removed_in_order(source: StaticSource) -> None:
    a, bb = b("2", "b-two"), b("1", "a-one")
    events, _ = run(
        source,
        [
            [a, bb],  # both appear: by name
            [a, bb],  # nothing changed
            [b("2", "b-two", revision=2), bb],  # a revision
            [bb],  # one is gone
        ],
    )
    kinds = [(e.kind, (e.binding or e.previous).name) for e in events]  # type: ignore[union-attr]
    assert kinds == [
        (EventKind.ADDED, "a-one"),
        (EventKind.ADDED, "b-two"),
        (EventKind.CHANGED, "b-two"),
        (EventKind.REMOVED, "b-two"),
    ]
    changed, removed = events[2], events[3]
    assert changed.binding.revision == 2 and changed.previous.revision == 1  # type: ignore[union-attr]
    assert removed.binding is None and removed.previous.revision == 2  # type: ignore[union-attr]


def test_a_failed_poll_keeps_the_state(source: StaticSource) -> None:
    one = b("1", "one")
    events, _ = run(source, [[one], Unavailable("down"), Unavailable("down"), [one]])
    assert [e.kind for e in events] == [EventKind.ADDED]  # no Removed, no second Added


def test_credentials_follow_new_and_changed_bindings(source: StaticSource) -> None:
    one = b("1", "one")
    reads: list[int] = []

    def credential(binding: Binding) -> Credential:
        reads.append(binding.revision)
        return cred(None)

    events, _ = run(source, [[one], [b("1", "one", revision=2)]], credentials=credential, watch_credentials=True)
    assert [e.kind for e in events] == [
        EventKind.ADDED,
        EventKind.CREDENTIAL_ROTATED,
        EventKind.CHANGED,
        EventKind.CREDENTIAL_ROTATED,
    ]
    assert reads == [1, 2]
    assert events[1].credential is not None and events[1].binding is not None and events[1].binding.id == "1"


def test_no_credentials_unless_asked(source: StaticSource) -> None:
    def credential(binding: Binding) -> Credential:
        raise AssertionError("not asked for")

    events, _ = run(source, [[b("1", "one")]], credentials=credential)
    assert [e.kind for e in events] == [EventKind.ADDED]


def test_rotation_at_two_thirds_of_a_lease(source: StaticSource) -> None:
    one = b("1", "one")
    clock: dict[str, Any] = {}
    n = []

    def credential(binding: Binding) -> Credential:
        n.append(1)
        return cred(90, clock["s"].now)

    stop = threading.Event()
    c = Client(address="x:1", server_id=LIGO_ID, x509_source=source, poll_interval=300)
    s = clock["s"] = Script(c, [[one]], stop)
    s.polls = [[one]] * 3  # the poll interval is long: only the lease wakes the watch
    c.credential = credential  # type: ignore[method-assign]
    got = []
    for e in c.watch(watch_credentials=True, stop=stop):
        got.append(e.kind)
        if len(got) == 3:
            stop.set()
    assert got == [EventKind.ADDED, EventKind.CREDENTIAL_ROTATED, EventKind.CREDENTIAL_ROTATED]
    assert s.sleeps[0] == pytest.approx(60)  # 2/3 of 90 s


def test_no_credential_is_not_retried(source: StaticSource) -> None:
    calls = []

    def credential(binding: Binding) -> Credential:
        calls.append(1)
        raise NoCredential("svid")

    events, _ = run(
        source, [[b("1", "one")], [b("1", "one")], [b("1", "one")]], credentials=credential, watch_credentials=True
    )
    assert [e.kind for e in events] == [EventKind.ADDED] and len(calls) == 1


def test_a_failed_credential_is_tried_at_the_next_poll(source: StaticSource, caplog: pytest.LogCaptureFixture) -> None:
    results: list[Any] = [StoreError("login: status 503"), cred(None)]

    def credential(binding: Binding) -> Credential:
        r = results.pop(0)
        if isinstance(r, Exception):
            raise r
        return r  # type: ignore[no-any-return]

    caplog.set_level(logging.WARNING, logger="ligo_client")
    events, _ = run(source, [[b("1", "one")], [b("1", "one")]], credentials=credential, watch_credentials=True)
    assert [e.kind for e in events] == [EventKind.ADDED, EventKind.CREDENTIAL_ROTATED]
    assert "credential not read" in caplog.text and "status 503" in caplog.text


# PY-12
def test_poll_cadence_has_jitter(source: StaticSource) -> None:
    _, s = run(source, [[b("1", "one")]] * 6, poll_interval=30)
    assert s.sleeps and all(30 <= w < 33.0001 for w in s.sleeps)
    assert len(set(s.sleeps)) > 1  # not a metronome


def test_backoff_doubles_to_five_minutes(source: StaticSource) -> None:
    _, s = run(source, [Unavailable("x")] * 9 + [[]], poll_interval=30)
    assert s.sleeps[:9] == [30, 60, 120, 240, 300, 300, 300, 300, 300]


def test_retry_after_wins_when_longer(source: StaticSource) -> None:
    _, s = run(source, [Unavailable("busy", retry_after=120), Unavailable("busy", retry_after=1), []], poll_interval=30)
    assert s.sleeps[:2] == [120, 60]


def test_a_success_resets_the_backoff(source: StaticSource) -> None:
    _, s = run(source, [Unavailable("x"), Unavailable("x"), [], Unavailable("x"), []], poll_interval=30)
    assert s.sleeps[0] == 30 and s.sleeps[1] == 60 and 30 <= s.sleeps[2] < 33.1 and s.sleeps[3] == 30


def test_the_stop_event_ends_the_watch(source: StaticSource) -> None:
    stop = threading.Event()
    stop.set()
    c = Client(address="x:1", server_id=LIGO_ID, x509_source=source)
    polled = []
    c.bindings = lambda *a, **k: polled.append(1) or []  # type: ignore[method-assign, assignment, func-returns-value]
    assert list(c.watch(stop=stop)) == [] and polled == []


def test_closing_the_client_ends_the_watch(source: StaticSource) -> None:
    c = Client(address="x:1", server_id=LIGO_ID, x509_source=source, poll_interval=5)
    c.bindings = lambda *a, **k: []  # type: ignore[method-assign, assignment]
    out: list[Any] = []
    t = threading.Thread(target=lambda: out.extend(c.watch()))
    t.start()
    c.close()
    t.join(timeout=5)
    assert not t.is_alive()


def test_closing_the_generator_ends_the_watch(source: StaticSource) -> None:
    stop = threading.Event()
    c = Client(address="x:1", server_id=LIGO_ID, x509_source=source)
    s = Script(c, [[b("1", "one")]] * 5, stop)
    gen: Iterator[Any] = c.watch(stop=stop)
    assert next(gen).kind == EventKind.ADDED
    gen.close()  # type: ignore[attr-defined]
    assert s.polled == 1


def test_event_text_hides_the_password(source: StaticSource) -> None:
    events, _ = run(
        source, [[b("1", "one")]], credentials=lambda binding: Credential("u", "hunter2"), watch_credentials=True
    )
    assert "hunter2" not in repr(events) and "hunter2" not in str(events[1])
