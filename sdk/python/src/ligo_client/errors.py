# SPDX-License-Identifier: MIT
"""The errors of the SDK. A message holds a status, never a body, a token or a password."""

from __future__ import annotations


class LigoError(Exception):
    """The base of every error the SDK raises on purpose."""


class Unauthorized(LigoError):
    """ligo or a store refused the workload, or the server is not the one the client accepts."""


class Unavailable(LigoError):
    """ligo or a store cannot answer now; try again, after `retry_after` seconds when it is set."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class NoCredential(LigoError):
    """The binding has no credential to read (its strategy is svid)."""


class UnsupportedStrategy(LigoError):
    """The binding's strategy is one this SDK does not know."""


class StoreNotAllowed(LigoError):
    """The secret store of the binding is not one the client may log in to."""


class StoreError(LigoError):
    """The secret store answered with an error."""
