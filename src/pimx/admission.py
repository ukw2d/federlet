"""Small local-admission helper for signed node manifests."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .models import Manifest
from .protocols import EvidenceVerifier
from .signing import check_manifest


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


async def domain_evidence_verifier(manifest: Manifest) -> tuple[bool, str]:
    """Minimal built-in verifier for ADR domain_proof evidence.

    This is deliberately not a DNS/CA proof. It only checks that the manifest's
    declared endpoint host is inside the declared domain. Stronger evidence
    types (SPIFFE, partner credentials, charter keys) belong behind host-supplied
    callbacks with their own trust material.
    """
    ev = manifest.admission_evidence or {}
    if ev.get("type") != "domain_proof":
        return False, "unsupported_evidence"
    domain = ev.get("domain")
    if not isinstance(domain, str) or not domain:
        return False, "bad_domain_evidence"
    host = (urlparse(manifest.endpoint).hostname or "").lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    if host == domain or host.endswith("." + domain):
        return True, "ok"
    return False, "domain_mismatch"


def _check_endpoint(endpoint: str, policy: AdmissionPolicy) -> str | None:
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return "bad_endpoint"
    if policy.require_https and parsed.scheme != "https":
        return "https_required"
    if policy.allowed_endpoint_domains and not any(
        host == d.lower().rstrip(".") or host.endswith("." + d.lower().rstrip("."))
        for d in policy.allowed_endpoint_domains
    ):
        return "endpoint_domain_denied"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if (
        not policy.allow_private_hosts
        and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    ):
        return "private_endpoint_denied"
    return None
