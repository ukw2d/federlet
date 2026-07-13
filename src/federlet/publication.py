"""Publication helpers for common node manifest setup."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._time import utc_now
from .crypto import public_jwk
from .models import (
    AdmissionEvidence,
    Disclosure,
    Manifest,
    ManifestLimits,
    Membership,
    PublicKey,
)
from .signing import sign_manifest


def build_signed_manifest(
    key: Ed25519PrivateKey,
    key_id: str,
    *,
    node_id: str,
    org_id: str,
    endpoint: str,
    federations: Iterable[str],
    protocol_versions: Iterable[str],
    manifest_url: str | None = None,
    revision: int = 1,
    bu_id: str | None = None,
    auth_methods: Iterable[str] = ("signed_http",),
    introduce_url: str | None = None,
    members_url: str | None = None,
    revocations_url: str | None = None,
    capability_summary_url: str | None = None,
    admission_evidence: AdmissionEvidence | None = None,
    disclosure: Disclosure | None = None,
    limits: ManifestLimits | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    ttl: timedelta | None = timedelta(days=7),
) -> Manifest:
    """Build and sign the standard manifest shape most nodes publish.

    The raw `Manifest` model and `sign_manifest` remain public for custom
    manifests. This helper only removes the repetitive Membership/PublicKey/
    timestamp wiring from the common case.
    """

    base = endpoint.rstrip("/")
    issued = issued_at or utc_now()
    expires = expires_at
    if expires is None and ttl is not None:
        expires = issued + ttl

    manifest = Manifest(
        node_id=node_id,
        org_id=org_id,
        bu_id=bu_id,
        federations=list(federations),
        endpoint=base,
        manifest_url=manifest_url,
        protocol_versions=list(protocol_versions),
        revision=revision,
        public_keys=[PublicKey(key_id=key_id, public_jwk=public_jwk(key))],
        auth_methods=list(auth_methods),
        membership=Membership(
            introduce_url=introduce_url or f"{base}/members/introduce",
            members_url=members_url or f"{base}/members",
            revocations_url=revocations_url,
        ),
        capability_summary_url=capability_summary_url,
        admission_evidence=admission_evidence,
        disclosure=disclosure,
        limits=limits,
        issued_at=issued,
        expires_at=expires,
    )
    return sign_manifest(manifest, key, key_id)
