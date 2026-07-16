"""Common high-level imports for host integrations.

This module is intentionally small compared with the root `federlet` namespace.
It contains the names most applications need to publish manifests, authenticate
inbound peer requests, admit peers, use the client, and exchange operation
envelopes. Lower-level signing and crypto primitives live in `federlet.lowlevel`.
"""

from .admission import AdmissionPolicy, admit_manifest
from .bootstrap import SeedBootstrapReport, bootstrap_from_seeds
from .certauth import (
    CertificateIdentity,
    CertVerifiedPeer,
    UnauthorizedCertificateIdentity,
    certificate_thumbprint,
    verify_certificate_identity,
)
from .client import SIGNATURE_HEADER, FederationClient
from .fanout import (
    OperationFanOutReport,
    OperationOutcome,
    OperationTarget,
    fan_out_operation,
)
from .membership import MembershipTable, self_scoped_authorize
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
from .refresh import ManifestRefreshDecision, RefreshTarget, refresh_all
from .responses import (
    sign_introduce_response,
    sign_members_response,
    sign_operation_response,
    sign_revocations_response,
)
from .signing import (
    UnauthorizedPeerRequest,
    VerifiedPeer,
    build_revocation,
    build_self_revocation,
    check_manifest,
    sign_manifest,
    verify_peer_request,
)
from .urls import well_known_url

__all__ = [
    "AdmissionPolicy",
    "CertificateIdentity",
    "CertVerifiedPeer",
    "FederationClient",
    "FederationNode",
    "Manifest",
    "Membership",
    "MembershipTable",
    "OperationFanOutReport",
    "OperationItem",
    "OperationOutcome",
    "OperationRequest",
    "OperationResponse",
    "OperationTarget",
    "PayloadProvenance",
    "PublicKey",
    "RefreshTarget",
    "SIGNATURE_HEADER",
    "SeedBootstrapReport",
    "ManifestRefreshDecision",
    "UnauthorizedCertificateIdentity",
    "UnauthorizedPeerRequest",
    "VerifiedPeer",
    "admit_manifest",
    "bootstrap_from_seeds",
    "build_revocation",
    "build_self_revocation",
    "certificate_thumbprint",
    "verify_certificate_identity",
    "fan_out_operation",
    "refresh_all",
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
    "self_scoped_authorize",
    "well_known_url",
]
