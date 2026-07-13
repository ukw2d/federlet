"""Capability-summary convenience helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._time import utc_now
from .models import CapabilitySummary
from .signing import sign_model


def sign_capability_summary(
    key: Ed25519PrivateKey,
    key_id: str,
    *,
    node_id: str,
    summary_version: int,
    coverage_text: str,
    record_types: Iterable[str] = (),
    facets: Mapping[str, Iterable[str]] | None = None,
    updated_at: datetime | None = None,
    expires_at: datetime | None = None,
    ttl: timedelta = timedelta(days=7),
) -> CapabilitySummary:
    """Build and sign a coarse capability summary for publication."""

    updated = updated_at or utc_now()
    expires = expires_at or updated + ttl
    summary = CapabilitySummary(
        node_id=node_id,
        summary_version=summary_version,
        record_types=list(record_types),
        facets={name: list(values) for name, values in (facets or {}).items()},
        coverage_text=coverage_text,
        updated_at=updated,
        expires_at=expires,
    )
    return sign_model(summary, key, key_id)
