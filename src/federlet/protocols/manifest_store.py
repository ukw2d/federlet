from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..models import Manifest


class ManifestStore(Protocol):
    """Async write-through durability port for admitted peers' manifests.

    ``peer_manifests`` remains the in-memory read cache on the hot inbound
    verification path (``FederationNode.verify_known_inbound``). This port is
    a durable sink plus a startup hydration source; federlet never performs
    point-wise request-time reads through it, so it deliberately has no
    ``get`` method.
    """

    async def upsert(self, manifest: Manifest) -> None: ...

    async def delete(self, node_id: str) -> None: ...

    async def values(self) -> list[Manifest]: ...
