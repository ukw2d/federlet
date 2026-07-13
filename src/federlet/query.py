"""Query envelope and signed result-reference helpers."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field

from .models import Manifest, Signature
from .signing import find_jwk, sign_model, verify_model


class QueryCriteria(BaseModel):
    """Host-owned query intent carried inside the standard query envelope."""

    model_config = ConfigDict(extra="allow")

    text: str | None = None
    filters: dict[str, Any] = Field(default_factory=dict)


class QueryRequest(BaseModel):
    """Peer-to-peer query request envelope.

    Federlet standardizes this wire shape only. Local parsing, planning,
    execution, ranking, and fan-out remain host responsibilities.
    """

    model_config = ConfigDict(extra="allow")

    query_id: str
    query: QueryCriteria
    requested_fields: list[str] = Field(default_factory=list)
    limit: int | None = Field(default=None, gt=0)
    timeout_ms: int | None = Field(default=None, gt=0)
    disclosure_context: dict[str, Any] = Field(default_factory=dict)


class ResultProvenance(BaseModel):
    """Provenance retained with a lightweight result reference after merging."""

    node_id: str
    content_hash: str


class ResultRef(BaseModel):
    """Lightweight signed reference returned by the owning node."""

    model_config = ConfigDict(extra="allow")

    record_id: str
    fetch_url: str
    revision: int | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: ResultProvenance
    signature: Signature | None = None


class Coverage(BaseModel):
    """Coverage metadata for a single node's local query execution."""

    model_config = ConfigDict(extra="allow")

    searched_local_catalogue: bool = True
    filtered_by_visibility: bool = True
    truncated: bool = False


class QueryResponse(BaseModel):
    """Peer-to-peer query response envelope."""

    query_id: str
    source_node_id: str
    results: list[ResultRef] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    signature: Signature | None = None


def sign_result(result: ResultRef, key: Ed25519PrivateKey, key_id: str) -> ResultRef:
    """Sign a result reference with the owning node's advertised signing key."""

    return sign_model(result, key, key_id)


def verify_result(owner_manifest: Manifest, result: ResultRef) -> bool:
    """Verify a result reference against the owning node's current manifest key."""

    if result.signature is None:
        return False
    if result.provenance.node_id != owner_manifest.node_id:
        return False
    jwk = find_jwk(owner_manifest.public_keys, result.signature.key_id)
    if jwk is None:
        return False
    return verify_model(result, jwk)
