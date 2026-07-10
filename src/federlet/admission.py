"""Small local-admission helper for signed node manifests."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Literal, Protocol
from urllib.parse import urlparse

from .models import DomainProofEvidence, Manifest
from .net import is_disallowed_ip
from .signing import check_manifest, verify_model


class EvidenceVerifier(Protocol):
    async def __call__(self, manifest: Manifest) -> tuple[bool, str]:
        """Verify host-owned admission evidence for a manifest (may do I/O)."""
        ...


@dataclass(frozen=True)
class AdmissionPolicy:
    federation_id: str
    protocol_versions: set[str]
    require_expires_at: bool = True
    require_signed_http: bool = True
    require_https: bool = True
    allow_private_hosts: bool = False
    allowed_endpoint_domains: set[str] = field(default_factory=set)
    evidence_verifier: EvidenceVerifier | None = None


@dataclass(frozen=True)
class AdmissionDecision:
    accepted: bool
    reason: str = "ok"


@dataclass(frozen=True)
class KeyContinuityPolicy:
    allow_key_rotation: bool = True
    evidence_verifier: EvidenceVerifier | None = None


@dataclass(frozen=True)
class KeyContinuityDecision:
    action: Literal["accept", "quarantine", "reject"]
    reason: str = "ok"


async def admit_manifest(
    manifest: Manifest,
    policy: AdmissionPolicy,
    *,
    max_skew_seconds: int = 300,
) -> AdmissionDecision:
    ok, reason = check_manifest(manifest, max_skew_seconds=max_skew_seconds)
    if not ok:
        return AdmissionDecision(False, reason)
    if policy.require_expires_at and not manifest.expires_at:
        return AdmissionDecision(False, "missing_expires_at")
    if policy.federation_id not in manifest.federations:
        return AdmissionDecision(False, "wrong_federation")
    if not set(manifest.protocol_versions) & policy.protocol_versions:
        return AdmissionDecision(False, "unsupported_protocol")
    if policy.require_signed_http and "signed_http" not in manifest.auth_methods:
        return AdmissionDecision(False, "signed_http_required")

    endpoint_reason = _check_endpoint(manifest.endpoint, policy)
    if endpoint_reason:
        return AdmissionDecision(False, endpoint_reason)

    if policy.evidence_verifier is not None:
        ok, reason = await policy.evidence_verifier(manifest)
        if not ok:
            return AdmissionDecision(False, reason)
    return AdmissionDecision(True)


async def check_key_continuity(
    old_manifest: Manifest,
    new_manifest: Manifest,
    policy: KeyContinuityPolicy | None = None,
) -> KeyContinuityDecision:
    """Decide whether a refreshed manifest preserves signing-key continuity."""
    policy = policy or KeyContinuityPolicy()
    if old_manifest.node_id != new_manifest.node_id:
        return KeyContinuityDecision("reject", "node_id_changed")
    if old_manifest.org_id != new_manifest.org_id:
        return KeyContinuityDecision("reject", "org_id_changed")

    old_keys = {key.key_id: key.public_jwk for key in old_manifest.public_keys}
    new_keys = {key.key_id: key.public_jwk for key in new_manifest.public_keys}
    if old_keys == new_keys:
        return KeyContinuityDecision("accept")

    if not policy.allow_key_rotation:
        return KeyContinuityDecision("reject", "rotation_denied")

    signature = new_manifest.signature
    if signature is not None:
        old_jwk = old_keys.get(signature.key_id)
        if old_jwk is not None and verify_model(new_manifest, old_jwk):
            return KeyContinuityDecision("accept", "signed_rotation")

    if policy.evidence_verifier is not None:
        ok, reason = await policy.evidence_verifier(new_manifest)
        if ok:
            return KeyContinuityDecision("accept", "admission_evidence")
        if reason == "rotation_denied":
            return KeyContinuityDecision("reject", reason)

    return KeyContinuityDecision("quarantine", "stale_manifest")


async def domain_evidence_verifier(manifest: Manifest) -> tuple[bool, str]:
    """Minimal built-in verifier for ADR domain_proof evidence.

    This is deliberately not a DNS/CA proof. It only checks that the manifest's
    declared endpoint host is inside the declared domain. Stronger evidence
    types (SPIFFE, partner credentials, charter keys) belong behind host-supplied
    callbacks with their own trust material.
    """
    ev = manifest.admission_evidence
    if not isinstance(ev, DomainProofEvidence):
        return False, "unsupported_evidence"
    if not ev.domain:
        return False, "bad_domain_evidence"
    if _host_in_domain(urlparse(manifest.endpoint).hostname or "", ev.domain):
        return True, "ok"
    return False, "domain_mismatch"


def _host_in_domain(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def _check_endpoint(endpoint: str, policy: AdmissionPolicy) -> str | None:
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return "bad_endpoint"
    if policy.require_https and parsed.scheme != "https":
        return "https_required"
    if policy.allowed_endpoint_domains and not any(
        _host_in_domain(host, d) for d in policy.allowed_endpoint_domains
    ):
        return "endpoint_domain_denied"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not policy.allow_private_hosts and is_disallowed_ip(ip):
        return "private_endpoint_denied"
    return None
