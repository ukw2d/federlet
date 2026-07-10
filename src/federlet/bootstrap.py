"""Seed-peer bootstrap helpers (ADR-005 §8.1)."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import ValidationError

from ._time import utc_now
from .admission import AdmissionPolicy, admit_manifest
from .client import FederationClient, ManifestVerificationError
from .crypto import b64u_encode
from .models import IntroduceRequest, IntroduceResponse, Manifest
from .net import SSRFError


@dataclass(frozen=True)
class SeedBootstrapOutcome:
    seed_manifest_url: str
    reason: str
    seed_manifest: Manifest | None = None
    response: IntroduceResponse | None = None


@dataclass(frozen=True)
class SeedBootstrapReport:
    accepted: list[SeedBootstrapOutcome]
    rejected: list[SeedBootstrapOutcome]
    failed: list[SeedBootstrapOutcome]


async def bootstrap_from_seeds(
    client: FederationClient,
    *,
    seed_manifest_urls: Iterable[str],
    local_manifest_url: str,
    local_manifest: Manifest,
    policy: AdmissionPolicy,
    requested_disclosure: str = "federation",
    max_skew_seconds: int = 300,
) -> SeedBootstrapReport:
    """Fetch, admit, and introduce this node to configured seed peers.

    This is a thin orchestration helper. It does not persist membership state:
    callers decide which accepted seed manifests and introduction responses to
    store in their own tables.
    """

    accepted: list[SeedBootstrapOutcome] = []
    rejected: list[SeedBootstrapOutcome] = []
    failed: list[SeedBootstrapOutcome] = []

    for seed_url in seed_manifest_urls:
        try:
            seed_manifest = await client.fetch_manifest(
                seed_url,
                max_skew_seconds=max_skew_seconds,
            )
        except Exception as exc:
            failed.append(SeedBootstrapOutcome(seed_url, _failure_reason(exc)))
            continue

        decision = await admit_manifest(
            seed_manifest,
            policy,
            max_skew_seconds=max_skew_seconds,
        )
        if not decision.accepted:
            rejected.append(
                SeedBootstrapOutcome(seed_url, decision.reason, seed_manifest)
            )
            continue

        intro = IntroduceRequest(
            federation_id=client.federation_id,
            manifest_url=local_manifest_url,
            manifest=local_manifest,
            requested_disclosure=requested_disclosure,
            nonce=b64u_encode(uuid.uuid4().bytes),
            timestamp=utc_now(),
        )
        try:
            response = await client.introduce(seed_manifest, intro)
        except Exception as exc:
            failed.append(
                SeedBootstrapOutcome(seed_url, _failure_reason(exc), seed_manifest)
            )
            continue

        outcome = SeedBootstrapOutcome(
            seed_url,
            response.reason or ("ok" if response.accepted else "rejected"),
            seed_manifest,
            response,
        )
        if response.accepted:
            accepted.append(outcome)
        else:
            rejected.append(outcome)

    return SeedBootstrapReport(accepted=accepted, rejected=rejected, failed=failed)


def _failure_reason(exc: Exception) -> str:
    if isinstance(exc, SSRFError):
        return "ssrf_rejected"
    if isinstance(exc, ManifestVerificationError):
        return str(exc) or "bad_manifest"
    if isinstance(exc, ValidationError):
        return "malformed_manifest"
    return exc.__class__.__name__
