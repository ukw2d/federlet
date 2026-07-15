"""Stateful facade over federlet's functional protocol core."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .admission import (
    AdmissionDecision,
    AdmissionPolicy,
    KeyContinuityPolicy,
    admit_manifest,
)
from .bootstrap import SeedBootstrapReport, bootstrap_from_seeds
from .client import FederationClient
from .crypto import JWK
from .discovery import DiscoveryRefreshReport, refresh_discovered_members
from .membership import (
    MemberRecord,
    MembershipTable,
    PeerState,
    admit,
    eligible_peers,
    set_state,
)
from .membership import (
    apply_revocation_notice as apply_membership_revocation_notice,
)
from .models import IntroduceRequest, IntroduceResponse, Manifest, RevocationNotice
from .protocols import ManifestStore, MembershipStore, NonceCache
from .refresh import (
    ManifestRefreshDecision,
    refresh_peer_manifest,
)
from .refresh import (
    refresh_all as refresh_all_manifests,
)
from .signing import (
    UnauthorizedPeerRequest,
    VerifiedPeer,
    sign_manifest,
    verify_peer_request,
)


@dataclass
class FederationNode:
    """Optional stateful facade for common host-side federation workflows.

    This class owns no HTTP routes, background jobs, durable persistence, or
    authorization logic. It binds common node identity/configuration once and
    delegates to the functional helpers that remain independently public.

    Membership state lives behind ``membership_table`` (a ``MembershipStore``
    port; inject a durable adapter for production). ``peer_manifests`` is the
    hot inbound verification cache. Optionally inject ``manifest_store`` as an
    async write-through sink and startup hydration source for that cache.
    """

    node_id: str
    federation_id: str
    key: Ed25519PrivateKey
    key_id: str
    admission_policy: AdmissionPolicy
    manifest_revision: int = 0
    membership_table: MembershipStore = field(default_factory=MembershipTable)
    manifest_store: ManifestStore | None = None
    peer_manifests: dict[str, Manifest] = field(default_factory=dict)
    nonce_cache: NonceCache | None = None
    allow_private: bool = False
    http_client: httpx.AsyncClient | None = None
    _lifecycle_lock: asyncio.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._lifecycle_lock = asyncio.Lock()
        self.client = FederationClient(
            node_id=self.node_id,
            federation_id=self.federation_id,
            key=self.key,
            key_id=self.key_id,
            manifest_revision=self.manifest_revision,
            allow_private=self.allow_private,
            client=self.http_client,
        )

    async def __aenter__(self) -> FederationNode:
        await self.hydrate()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self.client.close()

    async def hydrate(self) -> None:
        """Hydrate peer manifest cache from the optional durable store."""

        async with self._lifecycle_lock:
            if self.manifest_store is not None and not self.peer_manifests:
                self.peer_manifests = {
                    manifest.node_id: manifest
                    for manifest in await self.manifest_store.values()
                }

    async def verify_inbound(
        self,
        *,
        signature_header: str | None,
        peer_manifest: Manifest,
        method: str,
        path: str,
        body: bytes = b"",
        max_body_bytes: int | None = None,
        max_skew_seconds: int = 300,
    ) -> VerifiedPeer:
        """Verify one inbound signed peer request against a supplied manifest."""

        return await verify_peer_request(
            signature_header=signature_header,
            peer_manifest=peer_manifest,
            self_node_id=self.node_id,
            method=method,
            path=path,
            body=body,
            max_body_bytes=max_body_bytes,
            max_skew_seconds=max_skew_seconds,
            cache=self.nonce_cache,
        )

    async def verify_known_inbound(
        self,
        *,
        signature_header: str | None,
        source_node_id: str,
        method: str,
        path: str,
        body: bytes = b"",
        max_body_bytes: int | None = None,
        max_skew_seconds: int = 300,
    ) -> VerifiedPeer:
        """Verify an inbound request from a peer in this facade's manifest map."""

        peer_manifest = self.peer_manifests.get(source_node_id)
        if peer_manifest is None:
            raise UnauthorizedPeerRequest("unknown_peer")
        return await self.verify_inbound(
            signature_header=signature_header,
            peer_manifest=peer_manifest,
            method=method,
            path=path,
            body=body,
            max_body_bytes=max_body_bytes,
            max_skew_seconds=max_skew_seconds,
        )

    def sign_manifest(self, manifest: Manifest) -> Manifest:
        return sign_manifest(manifest, self.key, self.key_id)

    async def admit_peer(
        self,
        manifest: Manifest,
        *,
        manifest_url: str | None = None,
        max_skew_seconds: int = 300,
    ) -> AdmissionDecision:
        """Apply local admission policy and record an accepted peer locally."""

        decision = await admit_manifest(
            manifest,
            self.admission_policy,
            max_skew_seconds=max_skew_seconds,
        )
        if decision.accepted:
            resolved_url = manifest_url or manifest.manifest_url
            if resolved_url is None:
                return decision
            await self._record_peer(manifest, resolved_url)
        return decision

    async def introduce_to(
        self,
        peer_manifest: Manifest,
        intro: IntroduceRequest,
    ) -> IntroduceResponse:
        return await self.client.introduce(peer_manifest, intro)

    async def bootstrap_from_seeds(
        self,
        *,
        seed_manifest_urls: list[str],
        local_manifest_url: str,
        local_manifest: Manifest,
        requested_disclosure: str = "federation",
        max_skew_seconds: int = 300,
    ) -> SeedBootstrapReport:
        report = await bootstrap_from_seeds(
            self.client,
            seed_manifest_urls=seed_manifest_urls,
            local_manifest_url=local_manifest_url,
            local_manifest=local_manifest,
            policy=self.admission_policy,
            requested_disclosure=requested_disclosure,
            max_skew_seconds=max_skew_seconds,
        )
        for outcome in report.accepted:
            if outcome.seed_manifest is not None:
                await self._record_peer(
                    outcome.seed_manifest, outcome.seed_manifest_url
                )
        return report

    async def discover(
        self,
        *,
        max_skew_seconds: int = 300,
        per_peer_cap: int = 100,
        since: str | None = None,
    ) -> DiscoveryRefreshReport:
        report = await refresh_discovered_members(
            self.client,
            self.membership_table,
            self.peer_manifests,
            self.admission_policy,
            max_skew_seconds=max_skew_seconds,
            per_peer_cap=per_peer_cap,
            since=since,
        )
        for outcome in report.accepted:
            if outcome.manifest is not None:
                async with self._lifecycle_lock:
                    await self._remember_manifest(outcome.manifest)
        return report

    async def refresh_peer(
        self,
        node_id: str,
        *,
        key_continuity_policy: KeyContinuityPolicy | None = None,
        max_skew_seconds: int = 300,
    ) -> ManifestRefreshDecision:
        rec = await self.membership_table.get(node_id)
        manifest = self.peer_manifests.get(node_id)
        if rec is None or manifest is None:
            return ManifestRefreshDecision("reject", "unknown_peer")
        decision = await refresh_peer_manifest(
            self.client,
            manifest,
            rec.manifest_url,
            key_continuity_policy=key_continuity_policy,
            max_skew_seconds=max_skew_seconds,
        )
        await self._apply_refresh_decision(node_id, decision)
        return decision

    async def refresh_all(
        self,
        *,
        key_continuity_policy: KeyContinuityPolicy | None = None,
        max_skew_seconds: int = 300,
    ) -> dict[str, ManifestRefreshDecision]:
        targets = []
        decisions: dict[str, ManifestRefreshDecision] = {}
        for rec in list(await eligible_peers(self.membership_table)):
            manifest = self.peer_manifests.get(rec.node_id)
            if manifest is None:
                decision = ManifestRefreshDecision("reject", "unknown_peer")
                decisions[rec.node_id] = decision
                await self._apply_refresh_decision(rec.node_id, decision)
                continue
            targets.append((manifest, rec.manifest_url))

        decisions.update(
            await refresh_all_manifests(
                self.client,
                targets,
                key_continuity_policy=key_continuity_policy,
                max_skew_seconds=max_skew_seconds,
            )
        )
        for node_id, decision in decisions.items():
            await self._apply_refresh_decision(node_id, decision)
        return decisions

    async def select_peers(self, *, now: datetime | None = None) -> list[Manifest]:
        return [
            self.peer_manifests[rec.node_id]
            for rec in await eligible_peers(self.membership_table, now)
            if rec.node_id in self.peer_manifests
        ]

    async def apply_revocation_notice(
        self,
        notice: RevocationNotice,
        *,
        trusted_issuer_keys: Mapping[str, JWK],
    ) -> PeerState | None:
        """Apply a trusted revocation notice and evict the revoked manifest."""

        async with self._lifecycle_lock:
            state = await apply_membership_revocation_notice(
                self.membership_table,
                notice,
                federation_id=self.federation_id,
                trusted_issuer_keys=trusted_issuer_keys,
            )
            if state is PeerState.REVOKED:
                await self._forget_manifest(notice.revoked_node_id)
            return state

    async def _record_peer(self, manifest: Manifest, manifest_url: str) -> None:
        async with self._lifecycle_lock:
            await self._remember_manifest(manifest)
            await self.membership_table.upsert(
                admit(
                    MemberRecord(
                        node_id=manifest.node_id,
                        org_id=manifest.org_id,
                        manifest_url=manifest_url,
                        manifest_revision=manifest.revision,
                    )
                )
            )

    async def _apply_refresh_decision(
        self,
        node_id: str,
        decision: ManifestRefreshDecision,
    ) -> None:
        async with self._lifecycle_lock:
            rec = await self.membership_table.get(node_id)
            if (
                decision.action in {"accept", "unchanged"}
                and decision.manifest is not None
            ):
                await self._remember_manifest(decision.manifest)
                if rec is not None:
                    rec.manifest_revision = decision.manifest.revision
                    await self.membership_table.upsert(admit(rec))
            elif decision.action == "quarantine":
                if rec is not None:
                    await self.membership_table.upsert(
                        set_state(rec, PeerState.STALE_MANIFEST)
                    )
            elif decision.action == "reject":
                if rec is not None:
                    await self.membership_table.upsert(
                        set_state(rec, PeerState.REJECTED)
                    )
                await self._forget_manifest(node_id)

    async def _remember_manifest(self, manifest: Manifest) -> None:
        self.peer_manifests[manifest.node_id] = manifest
        if self.manifest_store is not None:
            await self.manifest_store.upsert(manifest)

    async def _forget_manifest(self, node_id: str) -> None:
        self.peer_manifests.pop(node_id, None)
        if self.manifest_store is not None:
            await self.manifest_store.delete(node_id)
