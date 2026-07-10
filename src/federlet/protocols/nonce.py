from __future__ import annotations

from typing import Protocol


class NonceCache(Protocol):
    """The one cache operation federlet needs for replay protection.

    `verify_signed_request` never constructs or configures a cache; it only
    calls `set(..., exist=False)` on whatever the host injects. A cashews
    `Cache` satisfies this structurally, so the host can pass one directly
    (mem:// for dev, redis:// or valkey in prod) with no adapter. Any other
    object with a compatible async `set` works too.
    """

    async def set(
        self,
        key: str,
        value: object,
        expire: float | None = None,
        exist: bool | None = None,
    ) -> bool:
        """Store `key`; with `exist=False` only if absent. True if it was stored."""
        ...
