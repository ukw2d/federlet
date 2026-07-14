"""One-shot manifest refresh decisions for host-owned scheduling."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from .admission import (
    KeyContinuityDecision,
    KeyContinuityPolicy,
    check_key_continuity,
)
from .client import FederationClient, ManifestVerificationError
from .models import Manifest
from .reasons import transport_failure_reason

RefreshTarget = tuple[Manifest, str]


@dataclass(frozen=True)
class ManifestRefreshDecision:
    action: Literal["unchanged", "accept", "quarantine", "reject"]
    reason: str = "ok"
    manifest: Manifest | None = None
    old_revision: int | None = None
    new_revision: int | None = None
    key_continuity: KeyContinuityDecision | None = None


async def refresh_peer_manifest(
    client: FederationClient,
    current_manifest: Manifest,
    manifest_url: str,
    *,
    key_continuity_policy: KeyContinuityPolicy | None = None,
    max_skew_seconds: int = 300,
) -> ManifestRefreshDecision:
    """Fetch and classify one accepted peer manifest refresh.

    Hosts own when to call this helper and how to persist the returned decision.
    This function intentionally does not schedule retries, loops, or background
    work.
    """
    old_revision = current_manifest.revision
    try:
        refreshed = await client.fetch_manifest(
            manifest_url,
            max_skew_seconds=max_skew_seconds,
        )
    except ManifestVerificationError as exc:
        reason = str(exc) or "bad_manifest"
        if reason in {"expired", "not_yet_valid"}:
            return ManifestRefreshDecision(
                "quarantine",
                "stale_manifest",
                old_revision=old_revision,
            )
        return ManifestRefreshDecision("reject", reason, old_revision=old_revision)
    except Exception as exc:
        reason = transport_failure_reason(exc)
        if reason is not None:
            return ManifestRefreshDecision(
                "quarantine",
                reason,
                old_revision=old_revision,
            )
        raise

    new_revision = refreshed.revision
    if new_revision < old_revision:
        return ManifestRefreshDecision(
            "reject",
            "revision_rollback",
            manifest=refreshed,
            old_revision=old_revision,
            new_revision=new_revision,
        )

    continuity = await check_key_continuity(
        current_manifest,
        refreshed,
        key_continuity_policy,
    )
    if continuity.action != "accept":
        return ManifestRefreshDecision(
            continuity.action,
            continuity.reason,
            manifest=refreshed,
            old_revision=old_revision,
            new_revision=new_revision,
            key_continuity=continuity,
        )

    if new_revision == old_revision:
        return ManifestRefreshDecision(
            "unchanged",
            manifest=refreshed,
            old_revision=old_revision,
            new_revision=new_revision,
            key_continuity=continuity,
        )

    return ManifestRefreshDecision(
        "accept",
        "revision_bump",
        manifest=refreshed,
        old_revision=old_revision,
        new_revision=new_revision,
        key_continuity=continuity,
    )


async def refresh_all(
    client: FederationClient,
    peers: Iterable[RefreshTarget],
    *,
    key_continuity_policy: KeyContinuityPolicy | None = None,
    max_skew_seconds: int = 300,
) -> dict[str, ManifestRefreshDecision]:
    """Refresh many peer manifests without owning persistence or state."""

    async def refresh_one(peer: Manifest, manifest_url: str):
        decision = await refresh_peer_manifest(
            client,
            peer,
            manifest_url,
            key_continuity_policy=key_continuity_policy,
            max_skew_seconds=max_skew_seconds,
        )
        return peer.node_id, decision

    return dict(await asyncio.gather(*(refresh_one(*peer) for peer in peers)))
