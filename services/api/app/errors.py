"""Typed HTTP errors. Shape matches the client contract: {error, code}."""

from __future__ import annotations


class ContractRevert(Exception):
    """Raised when the registry contract rejects a relayed transaction."""


class HttpError(Exception):
    def __init__(self, status: int, message: str, code: str = "error") -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code
