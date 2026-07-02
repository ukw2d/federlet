"""PIMX: Peer Introduction and Manifest Exchange.

A hubless HTTPS federation protocol for directory nodes (ADR-005).
"""

from .client import FederationClient, SSRFError
from .admission import (
    AdmissionDecision,
    AdmissionPolicy,
    admit_manifest,
    domain_evidence_verifier,
)
from .crypto import (
    canonical_bytes,
    generate_key,
    public_jwk,
    public_key_from_jwk,
    sign_bytes,
    verify_bytes,
)
from .membership import MemberRecord, MembershipTable, PeerState
from .models import (
    IntroduceRequest,
    IntroduceResponse,
    Manifest,
    MemberRef,
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
    sign_dict,
    sign_manifest,
    verify_dict,
    verify_manifest,
    verify_signed_request,
)

__all__ = [
    "FederationClient",
    "SSRFError",
    "AdmissionDecision",
    "AdmissionPolicy",
    "admit_manifest",
    "domain_evidence_verifier",
    "canonical_bytes",
    "generate_key",
    "public_jwk",
    "public_key_from_jwk",
    "sign_bytes",
    "verify_bytes",
    "MemberRecord",
    "MembershipTable",
    "PeerState",
    "IntroduceRequest",
    "IntroduceResponse",
    "Manifest",
    "MemberRef",
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
    "sign_dict",
    "sign_manifest",
    "verify_dict",
    "verify_manifest",
    "verify_signed_request",
]
