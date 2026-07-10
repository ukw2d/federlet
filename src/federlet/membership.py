"""Local membership table: admission state + health/cooldown."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING

from ._time import utc_now
from .crypto import JWK
from .models import MemberRef, RevocationNotice
from .signing import verify_revocation_notice

if TYPE_CHECKING:
    from .protocols import MembershipStore


class PeerState(str, Enum):
    ACTIVE = "active"
    COOLDOWN = "cooldown"
    STALE_MANIFEST = "stale_manifest"
    REJECTED = "rejected"
    REVOKED = "revoked"


@dataclass
class MemberRecord:
    node_id: str
    manifest_url: str
    org_id: str | None = None
    manifest_revision: int = 0
    state: PeerState = PeerState.ACTIVE
    accepted_until: datetime | None = None
    cooldown_until: datetime | None = None
    failures: int = 0
    last_refresh: datetime | None = None

    def is_eligible(self, now: datetime | None = None) -> bool:
        now = now or utc_now()
        if self.state != PeerState.ACTIVE:
            return False
        if self.accepted_until and now >= self.accepted_until:
            return False
        if self.cooldown_until and now < self.cooldown_until:
            return False
        return True


@dataclass
class DisclosurePolicy:
    default: str = "federation"
    denied: set[str] = field(default_factory=set)
    requester_disclosure: dict[str, str] = field(default_factory=dict)


class MembershipTable:
    def __init__(
        self,
        *,
        max_failures: int = 3,
        base_cooldown: timedelta = timedelta(seconds=30),
        max_cooldown: timedelta = timedelta(minutes=10),
    ) -> None:
        self._peers: dict[str, MemberRecord] = {}
        self.max_failures = max_failures
        self.base_cooldown = base_cooldown
        self.max_cooldown = max_cooldown

    def get(self, node_id: str) -> MemberRecord | None:
        return self._peers.get(node_id)

    def upsert(self, rec: MemberRecord) -> MemberRecord:
        self._peers[rec.node_id] = rec
        return rec

    def admit(self, rec: MemberRecord, accepted_until: datetime | None = None) -> None:
        rec.state = PeerState.ACTIVE
        rec.accepted_until = accepted_until
        rec.failures = 0
        rec.cooldown_until = None
        self._peers[rec.node_id] = rec

    def reject(self, node_id: str) -> None:
        self._set_state(node_id, PeerState.REJECTED)

    def revoke(self, node_id: str) -> None:
        self._set_state(node_id, PeerState.REVOKED)

    def mark_stale(self, node_id: str) -> None:
        self._set_state(node_id, PeerState.STALE_MANIFEST)

    def record_success(self, node_id: str) -> None:
        rec = self._peers.get(node_id)
        if rec is None:
            return
        rec.failures = 0
        rec.cooldown_until = None
        if rec.state == PeerState.COOLDOWN:
            rec.state = PeerState.ACTIVE

    def record_failure(self, node_id: str, now: datetime | None = None) -> None:
        rec = self._peers.get(node_id)
        if rec is None:
            return
        now = now or utc_now()
        rec.failures += 1
        backoff = min(self.base_cooldown * (2 ** (rec.failures - 1)), self.max_cooldown)
        rec.cooldown_until = now + backoff

    def eligible_peers(self, now: datetime | None = None) -> list[MemberRecord]:
        now = now or utc_now()
        return [r for r in self._peers.values() if r.is_eligible(now)]

    def _set_state(self, node_id: str, state: PeerState) -> None:
        rec = self._peers.get(node_id)
        if rec is not None:
            rec.state = state


def disclose_members(
    members: list[MemberRecord],
    requester_node_id: str,
    policy: DisclosurePolicy,
) -> list[MemberRef]:
    disclosure = policy.requester_disclosure.get(requester_node_id, policy.default)
    return [
        MemberRef(
            node_id=rec.node_id,
            org_id=rec.org_id,
            manifest_url=rec.manifest_url,
            manifest_revision=rec.manifest_revision,
            disclosure=disclosure,
        )
        for rec in members
        if rec.is_eligible() and rec.node_id not in policy.denied
    ]


def apply_revocation_notice(
    table: MembershipStore,
    notice: RevocationNotice,
    *,
    federation_id: str,
    trusted_issuer_keys: Mapping[str, JWK],
) -> PeerState | None:
    rec = table.get(notice.revoked_node_id)
    if rec is None:
        return None
    if notice.federation_id != federation_id or notice.signature is None:
        return rec.state
    jwk = trusted_issuer_keys.get(notice.signature.key_id)
    if jwk is None or not verify_revocation_notice(notice, jwk):
        return rec.state
    table.revoke(notice.revoked_node_id)
    return rec.state
