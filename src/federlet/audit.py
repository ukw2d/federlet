"""Pure audit-record builder for host logging sinks."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._time import iso_z, utc_now


def audit_record(
    *,
    event: str,
    request_id: str | None = None,
    operation_id: str | None = None,
    source_node_id: str | None = None,
    target_node_id: str | None = None,
    manifest_revision: int | None = None,
    decision: str | None = None,
    reason: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "timestamp": iso_z(utc_now()),
        "event": event,
    }
    optional = {
        "request_id": request_id,
        "operation_id": operation_id,
        "source_node_id": source_node_id,
        "target_node_id": target_node_id,
        "manifest_revision": manifest_revision,
        "decision": decision,
        "reason": reason,
    }
    record.update({key: value for key, value in optional.items() if value is not None})
    if extra:
        record.update({key: value for key, value in extra.items() if value is not None})
    return record
