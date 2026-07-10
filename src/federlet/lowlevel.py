"""Advanced primitives for tests, fixtures, and custom host adapters.

The root `federlet` package still re-exports these names for backwards
compatibility. New application code should prefer `federlet.prelude` unless it
needs direct access to canonicalization, detached signatures, or parsed signed
request envelopes.
"""

from .crypto import (
    JWK,
    b64u_decode,
    b64u_encode,
    canonical_bytes,
    generate_key,
    public_jwk,
    public_key_from_jwk,
)
from .models import Signature, SignedRequest
from .signing import (
    build_signed_request,
    check_body_size,
    find_jwk,
    sha256_hex,
    sign_dict,
    sign_model,
    verify_dict,
    verify_model,
    verify_signed_request,
)

__all__ = [
    "JWK",
    "Signature",
    "SignedRequest",
    "b64u_decode",
    "b64u_encode",
    "build_signed_request",
    "canonical_bytes",
    "check_body_size",
    "find_jwk",
    "generate_key",
    "public_jwk",
    "public_key_from_jwk",
    "sha256_hex",
    "sign_dict",
    "sign_model",
    "verify_dict",
    "verify_model",
    "verify_signed_request",
]
