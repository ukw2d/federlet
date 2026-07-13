"""Generic operation envelopes and signed payload-item helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field

from .models import Manifest, Signature
from .signing import find_jwk, sign_model, verify_model


class OperationRequest(BaseModel):
    """Peer-to-peer operation request envelope.

    Federlet standardizes identity, signing, and envelope shape only. Operation
    names, payload schema, metadata, routing, authorization, and execution
    semantics remain host-protocol responsibilities.
    """

    model_config = ConfigDict(extra="forbid")

    operation_id: str
    operation: str
    payload: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PayloadProvenance(BaseModel):
    """Provenance retained with a signed operation item after aggregation."""

    model_config = ConfigDict(extra="allow")

    node_id: str
    content_hash: str | None = None


class OperationItem(BaseModel):
    """Opaque host-owned payload item with optional provenance and signature."""

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any] = Field(default_factory=dict)
    provenance: PayloadProvenance | None = None
    signature: Signature | None = None


class OperationResponse(BaseModel):
    """Peer-to-peer operation response envelope."""

    model_config = ConfigDict(extra="forbid")

    operation_id: str
    source_node_id: str
    payload: dict[str, Any] = Field(default_factory=dict)
    items: list[OperationItem] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    signature: Signature | None = None


def build_operation_item(
    payload: BaseModel | Mapping[str, Any],
    *,
    provenance: PayloadProvenance | None = None,
) -> OperationItem:
    """Build an operation item from a Pydantic model or mapping payload."""

    if isinstance(payload, BaseModel):
        item_payload = payload.model_dump(mode="json", exclude_none=True)
    else:
        item_payload = dict(payload)
    return OperationItem(payload=item_payload, provenance=provenance)


def sign_operation_item(
    item: OperationItem, key: Ed25519PrivateKey, key_id: str
) -> OperationItem:
    """Sign an operation item with the owning node's advertised signing key."""

    return sign_model(item, key, key_id)


def sign_operation_payload(
    payload: BaseModel | Mapping[str, Any],
    *,
    key: Ed25519PrivateKey,
    key_id: str,
    provenance: PayloadProvenance | None = None,
) -> OperationItem:
    """Build and sign an operation item from a host-owned payload."""

    return sign_operation_item(
        build_operation_item(payload, provenance=provenance),
        key,
        key_id,
    )


def verify_operation_item(owner_manifest: Manifest, item: OperationItem) -> bool:
    """Verify an operation item against the owning node's current manifest key."""

    if item.signature is None:
        return False
    if (
        item.provenance is not None
        and item.provenance.node_id != owner_manifest.node_id
    ):
        return False
    jwk = find_jwk(owner_manifest.public_keys, item.signature.key_id)
    if jwk is None:
        return False
    return verify_model(item, jwk)
