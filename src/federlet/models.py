"""Pydantic wire models for the federation protocol (ADR-005)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_serializer

from ._time import iso_z
from .crypto import JWK


class Signature(BaseModel):
    key_id: str
    alg: str = "EdDSA"
    sig: str


class PublicKey(BaseModel):
    key_id: str
    use: str = "sig"
    alg: str = "EdDSA"
    public_jwk: JWK


class Membership(BaseModel):
    """Membership-exchange endpoints advertised by a manifest (ADR-005 §7)."""

    model_config = ConfigDict(extra="allow")

    introduce_url: str
    members_url: str
    revocations_url: str | None = None


class Disclosure(BaseModel):
    default: str
    supports_partner_scopes: bool


class ManifestLimits(BaseModel):
    max_query_rps_per_peer: int | None = None
    max_query_timeout_ms: int | None = None
    max_results: int | None = None


class GenericAdmissionEvidence(BaseModel):
    """Host-owned admission evidence with a tagged wire shape."""

    model_config = ConfigDict(extra="allow")

    type: str


class DomainProofEvidence(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["domain_proof"] = "domain_proof"
    domain: str


AdmissionEvidence = DomainProofEvidence | GenericAdmissionEvidence


class Manifest(BaseModel):
    node_id: str
    org_id: str
    bu_id: str | None = None
    federations: list[str] = Field(default_factory=list)
    endpoint: str
    manifest_url: str | None = None
    protocol_versions: list[str] = Field(default_factory=list)
    revision: int = 0
    public_keys: list[PublicKey] = Field(default_factory=list)
    auth_methods: list[str] = Field(default_factory=lambda: ["signed_http"])
    membership: Membership
    capability_summary_url: str | None = None
    admission_evidence: AdmissionEvidence | None = None
    disclosure: Disclosure | None = None
    limits: ManifestLimits | None = None
    issued_at: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    signature: Signature | None = None

    @field_serializer("issued_at", "expires_at", when_used="json")
    def _ser_ts(self, dt: datetime | None) -> str | None:
        return iso_z(dt)


class IntroduceRequest(BaseModel):
    federation_id: str
    manifest_url: str
    manifest: Manifest
    requested_disclosure: str = "federation"
    nonce: str
    timestamp: AwareDatetime

    @field_serializer("timestamp", when_used="json")
    def _ser_ts(self, dt: datetime) -> str:
        return iso_z(dt) or ""


class IntroduceResponse(BaseModel):
    accepted: bool
    accepted_node_id: str | None = None
    accepted_manifest_revision: int | None = None
    accepted_until: AwareDatetime | None = None
    reason: str | None = None
    membership_cursor: str | None = None
    known_peer_count: int | None = None
    signature: Signature | None = None

    @field_serializer("accepted_until", when_used="json")
    def _ser_ts(self, dt: datetime | None) -> str | None:
        return iso_z(dt)


class MemberRef(BaseModel):
    node_id: str
    org_id: str | None = None
    manifest_url: str
    manifest_revision: int | None = None
    disclosure: str = "federation"


class MembersResponse(BaseModel):
    source_node_id: str
    cursor: str | None = None
    members: list[MemberRef] = Field(default_factory=list)
    signature: Signature | None = None


class RevocationNotice(BaseModel):
    federation_id: str
    revoked_node_id: str
    reason: str
    issued_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    issuer: str
    signature: Signature | None = None

    @field_serializer("issued_at", "expires_at", when_used="json")
    def _ser_ts(self, dt: datetime | None) -> str | None:
        return iso_z(dt)


class RevocationsResponse(BaseModel):
    source_node_id: str
    cursor: str | None = None
    notices: list[RevocationNotice] = Field(default_factory=list)
    signature: Signature | None = None


class CapabilitySummary(BaseModel):
    node_id: str
    summary_version: int
    record_types: list[str] = Field(default_factory=list)
    facets: dict[str, list[str]] = Field(default_factory=dict)
    coverage_text: str
    updated_at: AwareDatetime
    expires_at: AwareDatetime
    signature: Signature | None = None

    @field_serializer("updated_at", "expires_at", when_used="json")
    def _ser_ts(self, dt: datetime) -> str:
        return iso_z(dt) or ""


class ProtocolResponse(BaseModel):
    """Lightweight protocol capability response from GET /protocol."""

    model_config = ConfigDict(extra="allow")

    protocol_versions: list[str] = Field(default_factory=list)
    auth_methods: list[str] = Field(default_factory=list)
    node_id: str | None = None
    manifest_revision: int | None = None
    limits: ManifestLimits | None = None


class HealthResponse(BaseModel):
    """Operational health response from GET /health."""

    model_config = ConfigDict(extra="allow")

    status: str = "ok"
    node_id: str | None = None


class SignedRequest(BaseModel):
    """Detached signed-request envelope sent alongside an HTTP call."""

    federation_id: str
    request_id: str
    source_node_id: str
    target_node_id: str
    method: str
    path: str
    timestamp: AwareDatetime
    nonce: str
    body_sha256: str
    source_manifest_revision: int = 0
    signature: Signature | None = None

    @field_serializer("timestamp", when_used="json")
    def _ser_ts(self, dt: datetime) -> str:
        return iso_z(dt) or ""
