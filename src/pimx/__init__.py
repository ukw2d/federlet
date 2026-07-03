"""PIMX: Peer Introduction and Manifest Exchange.

A hubless HTTPS federation protocol for directory nodes (ADR-005).
"""

from .client import Coverage, FederationClient, SkippedPeer, SSRFError
from .admission import (
    AdmissionDecision,
    AdmissionPolicy,
    admit_manifest,
    domain_evidence_verifier,
)
from .crypto import generate_key, public_jwk
from .membership import MemberRecord, MembershipTable, PeerState
from .models import (
    IntroduceRequest,
    IntroduceResponse,
    Manifest,
    MemberRef,
    Membership,
    MembersResponse,
    PublicKey,
    Query,
    QueryResponse,
    QueryResult,
    Signature,
    SignedRequest,
)
from .protocols import EvidenceVerifier, NonceCache
from .signing import (
    build_signed_request,
    check_manifest,
    find_jwk,
    sign_manifest,
    verify_manifest,
    verify_signed_request,
)

__all__ = [
    "Coverage",
    "FederationClient",
    "SkippedPeer",
    "SSRFError",
    "AdmissionDecision",
    "AdmissionPolicy",
    "admit_manifest",
    "domain_evidence_verifier",
    "generate_key",
    "public_jwk",
    "MemberRecord",
    "MembershipTable",
    "PeerState",
    "IntroduceRequest",
    "IntroduceResponse",
    "Manifest",
    "MemberRef",
    "Membership",
    "MembersResponse",
    "PublicKey",
    "Query",
    "QueryResponse",
    "QueryResult",
    "Signature",
    "SignedRequest",
    "EvidenceVerifier",
    "NonceCache",
    "build_signed_request",
    "check_manifest",
    "find_jwk",
    "sign_manifest",
    "verify_manifest",
    "verify_signed_request",
]
