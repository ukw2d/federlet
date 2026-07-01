"""Pydantic wire models for the federation protocol (ADR-005)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

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


class Manifest(BaseModel):
    node_id: str
    org_id: str
    bu_id: str | None = None
    federations: list[str] = Field(default_factory=list)
    endpoint: str
    protocol_versions: list[str] = Field(default_factory=list)
    revision: int = 0
    public_keys: list[PublicKey] = Field(default_factory=list)
    auth_methods: list[str] = Field(default_factory=lambda: ["signed_http"])
    membership: dict[str, str] = Field(default_factory=dict)
    admission_evidence: dict[str, Any] | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    signature: Signature | None = None


class IntroduceRequest(BaseModel):
    federation_id: str
    manifest_url: str
    manifest: Manifest
    requested_disclosure: str = "federation"
    nonce: str
    timestamp: str
    signature: Signature | None = None


class IntroduceResponse(BaseModel):
    accepted: bool
    accepted_node_id: str | None = None
    accepted_manifest_revision: int | None = None
    accepted_until: str | None = None
    reason: str | None = None
    membership_cursor: str | None = None
    signature: Signature | None = None


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


class SignedRequest(BaseModel):
    """Detached signed-request envelope sent alongside an HTTP call."""

    federation_id: str
    request_id: str
    source_node_id: str
    target_node_id: str
    method: str
    path: str
    timestamp: str
    nonce: str
    body_sha256: str
    source_manifest_revision: int = 0
    signature: Signature | None = None


class Query(BaseModel):
    query_id: str
    query: dict[str, Any]
    requested_fields: list[str] = Field(default_factory=list)
    limit: int = 20
    timeout_ms: int = 2000
    disclosure_context: dict[str, Any] = Field(default_factory=dict)


class QueryResult(BaseModel):
    record_id: str
    record_type: str | None = None
    name: str | None = None
    summary: str | None = None
    owner_org: str | None = None
    fetch_url: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)


class QueryResponse(BaseModel):
    query_id: str
    source_node_id: str
    results: list[QueryResult] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)
    signature: Signature | None = None
