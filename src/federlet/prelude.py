"""Common high-level imports for host integrations.

This module is intentionally small compared with the root `federlet` namespace.
It contains the names most applications need to publish manifests, authenticate
inbound peer requests, admit peers, use the client, and exchange query result
cards. Lower-level signing and crypto primitives live in `federlet.lowlevel`.
"""

from .admission import AdmissionPolicy, admit_manifest
from .bootstrap import SeedBootstrapReport, bootstrap_from_seeds
from .capability import sign_capability_summary
from .client import SIGNATURE_HEADER, FederationClient
from .membership import MembershipTable
from .models import Manifest, Membership, PublicKey
from .node import FederationNode
from .publication import build_signed_manifest
from .query import (
    QueryRequest,
    QueryResponse,
    ResultCard,
    sign_result_card,
    verify_result_card,
)
from .responses import (
    sign_introduce_response,
    sign_members_response,
    sign_query_response,
    sign_revocations_response,
)
from .signing import (
    UnauthorizedPeerRequest,
    VerifiedPeer,
    check_manifest,
    sign_manifest,
    verify_peer_request,
)

__all__ = [
    "AdmissionPolicy",
    "FederationClient",
    "FederationNode",
    "Manifest",
    "Membership",
    "MembershipTable",
    "PublicKey",
    "QueryRequest",
    "QueryResponse",
    "ResultCard",
    "SIGNATURE_HEADER",
    "SeedBootstrapReport",
    "UnauthorizedPeerRequest",
    "VerifiedPeer",
    "admit_manifest",
    "bootstrap_from_seeds",
    "build_signed_manifest",
    "check_manifest",
    "sign_capability_summary",
    "sign_introduce_response",
    "sign_manifest",
    "sign_members_response",
    "sign_query_response",
    "sign_revocations_response",
    "sign_result_card",
    "verify_peer_request",
    "verify_result_card",
]
