from __future__ import annotations

from typing import Protocol

from ..models import Manifest


class EvidenceVerifier(Protocol):
    async def __call__(self, manifest: Manifest) -> tuple[bool, str]:
        """Verify host-owned admission evidence for a manifest (may do I/O)."""
        ...
