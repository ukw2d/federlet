"""Common high-level imports for host integrations.

This module is intentionally small compared with the root `federlet` namespace.
It contains the names most applications need to publish manifests, authenticate
inbound peer requests, admit peers, use the client, and exchange operation
envelopes. Lower-level signing and crypto primitives live in `federlet.lowlevel`.
"""

from .admission import AdmissionPolicy, admit_manifest
from .bootstrap import SeedBootstrapReport, bootstrap_from_seeds
from .client import SIGNATURE_HEADER, FederationClient
from .membership import MembershipTable
from .models import Manifest, Membership, PublicKey
from .node import FederationNode
from .operations import (
    OperationItem,
    OperationRequest,
    OperationResponse,
    PayloadProvenance,
    build_operation_item,
    sign_operation_item,
    sign_operation_payload,
    verify_operation_item,
)
from .publication import build_signed_manifest
from .responses import (
    sign_introduce_response,
    sign_members_response,
    sign_operation_response,
    sign_revocations_response,
)
from .signing import (
    UnauthorizedPeerRequest,
    VerifiedPeer,
    check_manifest,
    sign_manifest,
    verify_peer_request,
)
from .urls import well_known_url

__all__ = [
    "AdmissionPolicy",
    "FederationClient",
    "FederationNode",
    "Manifest",
    "Membership",
    "MembershipTable",
    "OperationItem",
    "OperationRequest",
    "OperationResponse",
    "PayloadProvenance",
    "PublicKey",
    "SIGNATURE_HEADER",
    "SeedBootstrapReport",
    "UnauthorizedPeerRequest",
    "VerifiedPeer",
    "admit_manifest",
    "bootstrap_from_seeds",
    "build_signed_manifest",
    "build_operation_item",
    "check_manifest",
    "sign_introduce_response",
    "sign_operation_item",
    "sign_operation_payload",
    "sign_manifest",
    "sign_members_response",
    "sign_operation_response",
    "sign_revocations_response",
    "verify_peer_request",
    "verify_operation_item",
    "well_known_url",
]
