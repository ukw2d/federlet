"""Local membership: a thin storage default plus federlet-owned health policy.

The durability seam is the async ``MembershipStore`` port (see ``protocols``):
a host implements dumb CRUD (``get``/``upsert``/``values``/``delete``) backed
by redis/SQL/json.
Admission, backoff, and eligibility are *policy* — pure functions federlet
applies over the records a store holds, never methods an adapter must supply.
``MembershipTable`` is the optional in-memory reference implementation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import AwareDatetime, BaseModel, field_serializer

from ._time import iso_z, utc_now
from .crypto import JWK
from .models import MemberRef, RevocationNotice
from .signing import verify_revocation_notice

if TYPE_CHECKING:
    from .protocols import MembershipStore


def self_scoped_authorize(notice: RevocationNotice) -> bool:
    """Default ``authorize`` predicate: a node may only revoke itself.

    The semantic-trust counterpart to ``verify_revocation_notice``: where the
    signature check proves *who signed*, this proves *who is allowed to revoke
    whom*. Returning ``False`` rejects the notice regardless of signature.

    The default enforces self-scoped revocation (``issuer == revoked_node_id``),
    which is the safe behavior a host gets without supplying any policy. A host
    that wants cross-authority revocation (evicting a compromised node that will
    never self-revoke) passes its own closure built from its authority config;
    federlet never defines what "authority" or "scope" means. See ADR-005 §7.
    """

    return notice.issuer == notice.revoked_node_id


class PeerState(str, Enum):
    ACTIVE = "active"
    COOLDOWN = "cooldown"
    STALE_MANIFEST = "stale_manifest"
    REJECTED = "rejected"
    REVOKED = "revoked"


class MemberRecord(BaseModel):
    """Runtime membership state for one peer.

    A pydantic model so hosts persist and rehydrate it via ``model_dump``/
    ``model_validate`` (see the ``MembershipStore`` durability port) without a
    hand-rolled DTO. Mutated in place by the policy functions below.
    """

    node_id: str
    manifest_url: str
    org_id: str | None = None
    manifest_revision: int = 0
    state: PeerState = PeerState.ACTIVE
    accepted_until: AwareDatetime | None = None
    cooldown_until: AwareDatetime | None = None
    failures: int = 0
    last_refresh: AwareDatetime | None = None

    @field_serializer(
        "accepted_until", "cooldown_until", "last_refresh", when_used="json"
    )
    def _ser_ts(self, dt: datetime | None) -> str | None:
        return iso_z(dt)

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


# --- Health / backoff policy -------------------------------------------------
# Pure functions applied over records; a store persists the result via upsert.


@dataclass(frozen=True)
class CooldownPolicy:
    """Exponential backoff schedule for peer-refresh failures."""

    base_cooldown: timedelta = timedelta(seconds=30)
    max_cooldown: timedelta = timedelta(minutes=10)

    def next_cooldown(self, failures: int) -> timedelta:
        multiplier = 1 << max(failures - 1, 0)  # 2 ** (failures - 1), int-typed
        return min(self.base_cooldown * multiplier, self.max_cooldown)


DEFAULT_COOLDOWN_POLICY = CooldownPolicy()


def _touch(rec: MemberRecord, now: datetime | None) -> MemberRecord:
    """Stamp the lifecycle-write timestamp read by ``since`` disclosure cursors."""

    rec.last_refresh = now or utc_now()
    return rec


def admit(
    rec: MemberRecord,
    accepted_until: datetime | None = None,
    now: datetime | None = None,
) -> MemberRecord:
    """Mark a record admitted/active, clearing failure and cooldown state."""

    rec.state = PeerState.ACTIVE
    rec.accepted_until = accepted_until
    rec.failures = 0
    rec.cooldown_until = None
    return _touch(rec, now)


def set_state(
    rec: MemberRecord, state: PeerState, now: datetime | None = None
) -> MemberRecord:
    rec.state = state
    return _touch(rec, now)


def record_success(rec: MemberRecord, now: datetime | None = None) -> MemberRecord:
    rec.failures = 0
    rec.cooldown_until = None
    if rec.state == PeerState.COOLDOWN:
        rec.state = PeerState.ACTIVE
    return _touch(rec, now)


def record_failure(
    rec: MemberRecord,
    policy: CooldownPolicy = DEFAULT_COOLDOWN_POLICY,
    now: datetime | None = None,
) -> MemberRecord:
    now = now or utc_now()
    rec.failures += 1
    rec.cooldown_until = now + policy.next_cooldown(rec.failures)
    return _touch(rec, now)


async def eligible_peers(
    store: MembershipStore, now: datetime | None = None
) -> list[MemberRecord]:
    now = now or utc_now()
    return [r for r in await store.values() if r.is_eligible(now)]


class MembershipTable:
    """In-memory reference ``MembershipStore`` (optional default / test double)."""

    def __init__(self) -> None:
        self._peers: dict[str, MemberRecord] = {}

    async def get(self, node_id: str) -> MemberRecord | None:
        return self._peers.get(node_id)

    async def upsert(self, rec: MemberRecord) -> MemberRecord:
        self._peers[rec.node_id] = rec
        return rec

    async def values(self) -> list[MemberRecord]:
        return list(self._peers.values())

    async def delete(self, node_id: str) -> None:
        self._peers.pop(node_id, None)


def parse_since_cursor(since: str | datetime) -> datetime:
    """Normalize a ``since`` cursor to an aware UTC-comparable datetime.

    Accepts an ISO-8601 string (``Z`` or offset) or an already-parsed datetime.
    Raises ``ValueError`` on unparseable input or a naive datetime — callers
    (e.g. an HTTP route) map that to a 400 rather than guessing a timezone.
    """

    if isinstance(since, str):
        text = since.strip()
        try:
            since = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid since cursor: {since!r}") from exc
    if since.tzinfo is None:
        raise ValueError("since cursor must be timezone-aware")
    return since


def _disclosed_after(rec: MemberRecord, since: datetime) -> bool:
    """True if ``rec`` should be disclosed for the given ``since`` cursor.

    Records missing ``last_refresh`` are included (disclose-not-hide): once
    stamping is universal this only affects pre-migration records, and the set
    converges to empty as they are restamped.
    """

    return rec.last_refresh is None or rec.last_refresh > since


def disclose_members(
    members: list[MemberRecord],
    requester_node_id: str,
    policy: DisclosurePolicy,
    since: str | datetime | None = None,
) -> list[MemberRef]:
    disclosure = policy.requester_disclosure.get(requester_node_id, policy.default)
    cursor = parse_since_cursor(since) if since is not None else None
    return [
        MemberRef(
            node_id=rec.node_id,
            org_id=rec.org_id,
            manifest_url=rec.manifest_url,
            manifest_revision=rec.manifest_revision,
            disclosure=disclosure,
        )
        for rec in members
        if rec.is_eligible()
        and rec.node_id not in policy.denied
        and (cursor is None or _disclosed_after(rec, cursor))
    ]


async def apply_revocation_notice(
    table: MembershipStore,
    notice: RevocationNotice,
    *,
    federation_id: str,
    trusted_issuer_keys: Mapping[str, JWK],
    authorize: Callable[[RevocationNotice], bool] = self_scoped_authorize,
) -> PeerState | None:
    """Apply a trusted revocation notice to the local membership table.

    Two independent gates must pass before a record is marked ``REVOKED``:

    1. **Cryptographic authenticity** — ``trusted_issuer_keys`` +
       ``verify_revocation_notice`` prove the notice was signed by the holder of
       a key the caller trusts. The caller is responsible for ensuring a
       ``key_id`` in ``trusted_issuer_keys`` genuinely belongs to the claimed
       ``issuer``/authority (federlet does not maintain a key<->identity
       registry).
    2. **Semantic authorization** — ``authorize(notice)`` decides whether this
       ``issuer`` is allowed to revoke this ``revoked_node_id``. Defaults to
       :func:`self_scoped_authorize` (``issuer == revoked_node_id``); a host
       supplies its own closure to permit cross-authority revocation.

    Rejection paths (unknown node, federation mismatch, missing signature,
    unknown key, bad signature, or ``authorize`` returning ``False``) leave the
    record untouched and return its prior state. A successful revoke marks the
    record ``REVOKED`` in place and returns ``PeerState.REVOKED``; the
    ``FederationNode`` wrapper relies on that return value to evict the cached
    and durable manifest.
    """

    rec = await table.get(notice.revoked_node_id)
    if rec is None:
        return None
    if notice.federation_id != federation_id or notice.signature is None:
        return rec.state
    if not authorize(notice):
        return rec.state
    jwk = trusted_issuer_keys.get(notice.signature.key_id)
    if jwk is None or not verify_revocation_notice(notice, jwk):
        return rec.state
    await table.upsert(set_state(rec, PeerState.REVOKED))
    return rec.state
