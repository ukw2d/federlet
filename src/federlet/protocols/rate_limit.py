from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from ..models import ManifestLimits


class RateLimiter(Protocol):
    """Per-peer rate-limit port for host-provided backends."""

    async def allow(self, peer_node_id: str, *, now: float) -> bool:
        """Return True when the peer may spend one request token."""
        ...


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class TokenBucketRateLimiter:
    """Small in-memory reference limiter keyed by peer node_id."""

    def __init__(self, peer_limits: Mapping[str, ManifestLimits | None]) -> None:
        self._peer_limits = dict(peer_limits)
        self._buckets: dict[str, _Bucket] = {}

    async def allow(self, peer_node_id: str, *, now: float) -> bool:
        limits = self._peer_limits.get(peer_node_id)
        rate = limits.max_operation_rps_per_peer if limits else None
        if rate is None:
            return True
        if rate <= 0:
            return False

        bucket = self._buckets.setdefault(peer_node_id, _Bucket(float(rate), now))
        elapsed = max(0.0, now - bucket.updated_at)
        if elapsed:
            bucket.tokens = min(float(rate), bucket.tokens + elapsed * rate)
            bucket.updated_at = now

        if bucket.tokens < 1.0:
            return False
        bucket.tokens -= 1.0
        return True
