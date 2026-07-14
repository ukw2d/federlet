"""Discovered-peer admission from signed membership hints."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from json import JSONDecodeError

from pydantic import ValidationError

from .admission import AdmissionPolicy, admit_manifest
from .client import FederationClient, ManifestVerificationError
from .membership import MemberRecord
from .models import Manifest, MemberRef
from .protocols import MembershipStore
from .reasons import transport_failure_reason


@dataclass(frozen=True)
class DiscoveryOutcome:
    node_id: str
    manifest_url: str
    source_node_id: str
    reason: str = "ok"
    manifest: Manifest | None = None


@dataclass(frozen=True)
class DiscoveryRefreshReport:
    accepted: list[DiscoveryOutcome]
    rejected: list[DiscoveryOutcome]
    skipped: list[DiscoveryOutcome]
    failed: list[DiscoveryOutcome]


@dataclass
class _DiscoveryAccumulator:
    accepted: list[DiscoveryOutcome] = field(default_factory=list)
    rejected: list[DiscoveryOutcome] = field(default_factory=list)
    skipped: list[DiscoveryOutcome] = field(default_factory=list)
    failed: list[DiscoveryOutcome] = field(default_factory=list)

    def to_report(self) -> DiscoveryRefreshReport:
        return DiscoveryRefreshReport(
            accepted=self.accepted,
            rejected=self.rejected,
            skipped=self.skipped,
            failed=self.failed,
        )


async def refresh_discovered_members(
    client: FederationClient,
    table: MembershipStore,
    peer_manifests: Mapping[str, Manifest],
    policy: AdmissionPolicy,
    *,
    max_skew_seconds: int = 300,
    per_peer_cap: int = 100,
    since: str | None = None,
) -> DiscoveryRefreshReport:
    """Fetch and locally admit newly discovered peers from eligible members.

    Membership responses are only discovery hints. Each discovered manifest is
    fetched and admitted against the caller's local policy before the table is
    updated.
    """
    outcomes = _DiscoveryAccumulator()
    seen_node_ids: set[str] = set()
    seen_manifest_urls: set[str] = set()

    for rec in table.eligible_peers():
        peer_manifest = peer_manifests.get(rec.node_id)
        if peer_manifest is None:
            outcomes.failed.append(_outcome_from_record(rec, "missing_peer_manifest"))
            continue

        try:
            members = await client.get_members(peer_manifest, since=since)
        except Exception as exc:
            outcomes.failed.append(_outcome_from_record(rec, _failure_reason(exc)))
            continue

        for index, ref in enumerate(members.members):
            outcome = DiscoveryOutcome(
                node_id=ref.node_id,
                manifest_url=ref.manifest_url,
                source_node_id=peer_manifest.node_id,
            )
            if index >= per_peer_cap:
                outcomes.skipped.append(_with_reason(outcome, "per_peer_cap"))
                continue
            if ref.node_id == client.node_id:
                outcomes.skipped.append(_with_reason(outcome, "self"))
                continue
            if table.get(ref.node_id) is not None:
                outcomes.skipped.append(_with_reason(outcome, "existing_peer"))
                continue
            if ref.node_id in seen_node_ids or ref.manifest_url in seen_manifest_urls:
                outcomes.skipped.append(_with_reason(outcome, "duplicate"))
                continue

            seen_node_ids.add(ref.node_id)
            seen_manifest_urls.add(ref.manifest_url)
            await _process_ref(
                client,
                table,
                policy,
                ref,
                peer_manifest.node_id,
                max_skew_seconds,
                outcomes,
            )

    return outcomes.to_report()


async def _process_ref(
    client: FederationClient,
    table: MembershipStore,
    policy: AdmissionPolicy,
    ref: MemberRef,
    source_node_id: str,
    max_skew_seconds: int,
    outcomes: _DiscoveryAccumulator,
) -> None:
    base = DiscoveryOutcome(ref.node_id, ref.manifest_url, source_node_id)
    try:
        manifest = await client.fetch_manifest(
            ref.manifest_url,
            max_skew_seconds=max_skew_seconds,
        )
    except Exception as exc:
        outcomes.failed.append(_with_reason(base, _failure_reason(exc)))
        return

    if manifest.node_id != ref.node_id:
        outcomes.skipped.append(_with_manifest(base, "node_id_mismatch", manifest))
        return
    if manifest.node_id == client.node_id:
        outcomes.skipped.append(_with_manifest(base, "self", manifest))
        return

    decision = await admit_manifest(
        manifest,
        policy,
        max_skew_seconds=max_skew_seconds,
    )
    if not decision.accepted:
        outcomes.rejected.append(_with_manifest(base, decision.reason, manifest))
        return

    table.admit(
        MemberRecord(
            node_id=manifest.node_id,
            org_id=manifest.org_id,
            manifest_url=ref.manifest_url,
            manifest_revision=manifest.revision,
        )
    )
    outcomes.accepted.append(_with_manifest(base, "ok", manifest))


def _outcome_from_record(rec: MemberRecord, reason: str) -> DiscoveryOutcome:
    return DiscoveryOutcome(
        node_id=rec.node_id,
        manifest_url=rec.manifest_url,
        source_node_id=rec.node_id,
        reason=reason,
    )


def _with_reason(outcome: DiscoveryOutcome, reason: str) -> DiscoveryOutcome:
    return DiscoveryOutcome(
        node_id=outcome.node_id,
        manifest_url=outcome.manifest_url,
        source_node_id=outcome.source_node_id,
        reason=reason,
    )


def _with_manifest(
    outcome: DiscoveryOutcome,
    reason: str,
    manifest: Manifest,
) -> DiscoveryOutcome:
    return DiscoveryOutcome(
        node_id=outcome.node_id,
        manifest_url=outcome.manifest_url,
        source_node_id=outcome.source_node_id,
        reason=reason,
        manifest=manifest,
    )


def _failure_reason(exc: Exception) -> str:
    match exc:
        case ManifestVerificationError():
            return str(exc) or "bad_manifest"
        case ValidationError() | JSONDecodeError():
            return "malformed_manifest"
    return transport_failure_reason(exc) or exc.__class__.__name__
