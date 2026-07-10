from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..membership import MemberRecord


class MembershipStore(Protocol):
    """Persistence port for host-owned membership state."""

    def get(self, node_id: str) -> MemberRecord | None: ...

    def upsert(self, rec: MemberRecord) -> MemberRecord: ...

    def admit(
        self, rec: MemberRecord, accepted_until: datetime | None = None
    ) -> None: ...

    def reject(self, node_id: str) -> None: ...

    def revoke(self, node_id: str) -> None: ...

    def mark_stale(self, node_id: str) -> None: ...

    def record_success(self, node_id: str) -> None: ...

    def record_failure(self, node_id: str, now: datetime | None = None) -> None: ...

    def eligible_peers(self, now: datetime | None = None) -> list[MemberRecord]: ...
