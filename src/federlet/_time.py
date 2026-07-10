"""Shared UTC timestamp helpers."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_z(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
