# SPDX-License-Identifier: MIT
"""Watching the workload's bindings (.specs/ligo-client-sdk.md §3.5)."""

from __future__ import annotations

import enum
import random
from dataclasses import dataclass

from .store import Credential
from .types import Binding

MAX_BACKOFF = 300.0  # seconds


class EventKind(str, enum.Enum):
    ADDED = "added"  # a binding appeared; also every binding at the first poll
    CHANGED = "changed"  # a known binding has another revision
    REMOVED = "removed"  # a known binding is gone: revoked or expired
    CREDENTIAL_ROTATED = "credential_rotated"  # a credential was read for the binding

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Event:
    """One change seen by watch."""

    kind: EventKind
    binding: Binding | None = None  # the binding now; None for removed
    previous: Binding | None = None  # the binding before; set for changed and removed
    credential: Credential | None = None  # set for credential_rotated


def jitter(poll: float) -> float:
    """The wait between two polls: the interval and up to a tenth more."""
    return poll + random.uniform(0, poll / 10)  # noqa: S311 - jitter, not a secret
