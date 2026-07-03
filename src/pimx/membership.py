"""Local membership table: admission state + health/cooldown."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from ._time import utc_now


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
