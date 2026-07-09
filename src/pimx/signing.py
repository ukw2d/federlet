"""Sign/verify manifests and signed-request envelopes."""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta
from typing import TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from ._time import utc_now
from .crypto import JWK, b64u_encode, canonical_bytes, sign_bytes, verify_bytes
from .models import Manifest, PublicKey, RevocationNotice, Signature, SignedRequest
from .protocols.nonce import NonceCache

M = TypeVar("M", bound=BaseModel)


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _nonce_cache_key(env: SignedRequest) -> str:
    return (
        "pimx:nonce:"
        f"{env.federation_id}:{env.source_node_id}:{env.target_node_id}:{env.nonce}"
    )


def find_jwk(keys: list[PublicKey], key_id: str) -> JWK | None:
    """Look up an advertised public JWK by key_id."""
    return next((k.public_jwk for k in keys if k.key_id == key_id), None)


def sign_dict(payload: dict, key: Ed25519PrivateKey, key_id: str) -> dict:
    """Attach a detached signature over the payload minus its signature field."""
    body = {k: v for k, v in payload.items() if k != "signature"}
    sig = sign_bytes(key, canonical_bytes(body))
    signed = dict(payload)
    signed["signature"] = Signature(key_id=key_id, sig=sig).model_dump()
    return signed


def verify_dict(payload: dict, jwk: JWK) -> bool:
    sig = payload.get("signature")
    if not sig:
        return False
    body = {k: v for k, v in payload.items() if k != "signature"}
    return verify_bytes(jwk, sig["sig"], canonical_bytes(body))


def sign_model(model: M, key: Ed25519PrivateKey, key_id: str) -> M:
    """Sign a model's canonical JSON and return the re-validated, signed copy."""
    data = sign_dict(model.model_dump(mode="json", exclude_none=True), key, key_id)
    return model.__class__.model_validate(data)


def verify_model(model: BaseModel, jwk: JWK) -> bool:
    return verify_dict(model.model_dump(mode="json", exclude_none=True), jwk)


# --- Manifests ---------------------------------------------------------------


def sign_manifest(manifest: Manifest, key: Ed25519PrivateKey, key_id: str) -> Manifest:
    return sign_model(manifest, key, key_id)


def check_manifest(manifest: Manifest, *, max_skew_seconds: int = 300) -> tuple[bool, str]:
    """Verify a manifest's signature AND freshness. Returns (ok, reason).

    Freshness (issued_at/expires_at) is checked only when present; an "expired"
    or "not_yet_valid" reason should map to stale_manifest, a bad signature to
    reject. ADR-005 §7.
    """
    if manifest.signature is None:
        return False, "unsigned"
    jwk = find_jwk(manifest.public_keys, manifest.signature.key_id)
    if jwk is None:
        return False, "unknown_key"
    if not verify_model(manifest, jwk):
        return False, "bad_signature"
    now = utc_now()
    skew = timedelta(seconds=max_skew_seconds)
    if manifest.expires_at and now > manifest.expires_at + skew:
        return False, "expired"
    if manifest.issued_at and now < manifest.issued_at - skew:
        return False, "not_yet_valid"
    return True, "ok"


def verify_manifest(manifest: Manifest, *, max_skew_seconds: int = 300) -> bool:
    """True only if the manifest's signature is valid and it is currently fresh."""
    ok, _ = check_manifest(manifest, max_skew_seconds=max_skew_seconds)
    return ok


def verify_response_signature(peer_manifest: Manifest, response: BaseModel) -> bool:
    """Verify a signed response against the owning peer's advertised key."""
    signature = getattr(response, "signature", None)
    if signature is None:
        return False
    jwk = find_jwk(peer_manifest.public_keys, signature.key_id)
    if jwk is None:
        return False
    return verify_model(response, jwk)


def verify_revocation_notice(notice: RevocationNotice, jwk: JWK) -> bool:
    return verify_model(notice, jwk)


# --- Signed request envelopes ------------------------------------------------


def build_signed_request(
    key: Ed25519PrivateKey,
    key_id: str,
    *,
    federation_id: str,
    source_node_id: str,
    target_node_id: str,
    method: str,
    path: str,
    body: bytes = b"",
    source_manifest_revision: int = 0,
) -> SignedRequest:
    env = SignedRequest(
        federation_id=federation_id,
        request_id=str(uuid.uuid4()),
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        method=method.upper(),
        path=path,
        timestamp=utc_now(),
        nonce=b64u_encode(uuid.uuid4().bytes),
        body_sha256=sha256_hex(body),
        source_manifest_revision=source_manifest_revision,
    )
    return sign_model(env, key, key_id)


async def verify_signed_request(
    env: SignedRequest,
    jwk: JWK,
    *,
    self_node_id: str,
    method: str,
    path: str,
    body: bytes = b"",
    max_skew_seconds: int = 300,
    cache: NonceCache | None = None,
) -> tuple[bool, str]:
    """Returns (ok, reason). Caller supplies the signer's current JWK.

    `method` and `path` must come from the actual inbound HTTP request, not
    from the signed envelope. They bind the signature to the route handling the
    request and must be checked before a nonce is claimed.

    When `cache` is given (any NonceCache the host injects), the nonce is
    claimed for replay protection. The claim happens only AFTER the signature
    verifies and its TTL equals the skew window, so unauthenticated requests can
    neither burn nonces nor leave the store and the skew window out of sync.
    If `cache` is omitted, verification still checks authenticity and freshness,
    but replay protection is disabled.
    """
    if env.signature is None:
        return False, "unsigned"
    if env.target_node_id != self_node_id:
        return False, "wrong_target"
    if env.method != method.upper():
        return False, "method_mismatch"
    if env.path != path:
        return False, "path_mismatch"
    if env.body_sha256 != sha256_hex(body):
        return False, "body_mismatch"
    if abs((utc_now() - env.timestamp).total_seconds()) > max_skew_seconds:
        return False, "stale_timestamp"
    if not verify_model(env, jwk):
        return False, "bad_signature"
    if cache is not None:
        claimed = await cache.set(
            _nonce_cache_key(env), 1, expire=max_skew_seconds, exist=False
        )
        if not claimed:
            return False, "replay"
    return True, "ok"
