"""PIMX: Peer Introduction and Manifest Exchange.

A hubless HTTPS federation protocol for directory nodes (ADR-005).
"""

from .client import (
    SIGNATURE_HEADER,
    FederationClient,
    ManifestVerificationError,
    ResponseSignatureError,
)
from .admission import (
    AdmissionDecision,
    AdmissionPolicy,
    EvidenceVerifier,
    admit_manifest,
    domain_evidence_verifier,
)
from .crypto import (
    JWK,
    b64u_decode,
    b64u_encode,
    canonical_bytes,
    generate_key,
    public_jwk,
    public_key_from_jwk,
)
from .membership import MemberRecord, MembershipTable, PeerState
from .net import SSRFError
from .models import (
    IntroduceRequest,
    IntroduceResponse,
    Manifest,
    MemberRef,
    Membership,
    MembersResponse,
    PublicKey,
    Signature,
    SignedRequest,
)
from .protocols import NonceCache
from .signing import (
    build_signed_request,
    check_manifest,
    find_jwk,
    sha256_hex,
    sign_dict,
    sign_manifest,
    sign_model,
    verify_dict,
    verify_manifest,
    verify_model,
    verify_signed_request,
)

__all__ = [
    "FederationClient",
    "ManifestVerificationError",
    "ResponseSignatureError",
    "SIGNATURE_HEADER",
    "SSRFError",
    "AdmissionDecision",
    "AdmissionPolicy",
    "admit_manifest",
    "domain_evidence_verifier",
    "JWK",
    "b64u_decode",
    "b64u_encode",
    "canonical_bytes",
    "generate_key",
    "public_jwk",
    "public_key_from_jwk",
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
    "Signature",
    "SignedRequest",
    "EvidenceVerifier",
    "NonceCache",
    "build_signed_request",
    "check_manifest",
    "find_jwk",
    "sha256_hex",
    "sign_dict",
    "sign_manifest",
    "sign_model",
    "verify_dict",
    "verify_manifest",
    "verify_model",
    "verify_signed_request",
]
