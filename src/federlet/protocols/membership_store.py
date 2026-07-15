from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..membership import MemberRecord


class MembershipStore(Protocol):
    """Thin storage port for host-owned membership state (CRUD only).

    Adapters implement plain persistence — redis/SQL/json in ~10 lines.
    Admission, backoff, and eligibility are federlet-owned policy applied over
    the records this store holds (see ``membership`` module), never methods an
    adapter must supply.
    """

    async def get(self, node_id: str) -> MemberRecord | None: ...

    async def upsert(self, rec: MemberRecord) -> MemberRecord: ...

    async def values(self) -> list[MemberRecord]: ...

    async def delete(self, node_id: str) -> None: ...
