"""Sign/verify manifests and signed-request envelopes."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import JWK, b64u_encode, canonical_bytes, sign_bytes, verify_bytes
from .models import Manifest, Signature, SignedRequest


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sign_dict(payload: dict, key: Ed25519PrivateKey, key_id: str) -> dict:
    """Attach a detached signature over the payload minus its signature field."""
    body = {k: v for k, v in payload.items() if k != "signature"}
    sig = sign_bytes(key, canonical_bytes(body))
    payload["signature"] = Signature(key_id=key_id, sig=sig).model_dump()
    return payload


def verify_dict(payload: dict, jwk: JWK) -> bool:
    sig = payload.get("signature")
    if not sig:
        return False
    body = {k: v for k, v in payload.items() if k != "signature"}
    return verify_bytes(jwk, sig["sig"], canonical_bytes(body))


# --- Manifests ---------------------------------------------------------------


def sign_manifest(manifest: Manifest, key: Ed25519PrivateKey, key_id: str) -> Manifest:
    data = sign_dict(manifest.model_dump(exclude_none=True), key, key_id)
    return Manifest.model_validate(data)


def _parse_iso(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _check_window(
    raw: str | None,
    *,
    now: datetime,
    skew: timedelta,
    unparseable_reason: str,
    out_of_window_reason: str,
    predicate: Callable[[datetime, datetime, timedelta], bool],
) -> str | None:
    """Validate an optional ISO timestamp with a skew window.

    Returns None if the field is absent or in-window. `predicate(now, parsed,
    skew)` should return True when the timestamp is OUT of the acceptable
    window. For expires_at the predicate is `now > parsed + skew`; for
    issued_at it is `now < parsed - skew`. Keeping the predicate explicit at
    the call site (rather than parameterising "which side") makes it
    impossible to wire up the wrong direction silently.
    """
    if not raw:
        return None
    parsed = _parse_iso(raw)
    if parsed is None:
        return unparseable_reason
    if predicate(now, parsed, skew):
        return out_of_window_reason
    return None


def check_manifest(manifest: Manifest, *, max_skew_seconds: int = 300) -> tuple[bool, str]:
    """Verify a manifest's signature AND freshness. Returns (ok, reason).

    Freshness (issued_at/expires_at) is checked only when present; an "expired"
    or "not_yet_valid" reason should map to stale_manifest, a bad signature to
    reject. ADR-005 §7.
    """
    if manifest.signature is None:
        return False, "unsigned"
    jwk = next(
        (k.public_jwk for k in manifest.public_keys
         if k.key_id == manifest.signature.key_id),
        None,
    )
    if jwk is None:
        return False, "unknown_key"
    if not verify_dict(manifest.model_dump(exclude_none=True), jwk):
        return False, "bad_signature"
    now = _now()
    skew = timedelta(seconds=max_skew_seconds)
    reason = _check_window(
        manifest.expires_at,
        now=now, skew=skew,
        unparseable_reason="bad_expires_at",
        out_of_window_reason="expired",
        predicate=lambda n, p, s: n > p + s,
    )
    if reason is None:
        reason = _check_window(
            manifest.issued_at,
            now=now, skew=skew,
            unparseable_reason="bad_issued_at",
            out_of_window_reason="not_yet_valid",
            predicate=lambda n, p, s: n < p - s,
        )
    if reason is not None:
        return False, reason
    return True, "ok"


def verify_manifest(manifest: Manifest, *, max_skew_seconds: int = 300) -> bool:
    """True only if the manifest's signature is valid and it is currently fresh."""
    ok, _ = check_manifest(manifest, max_skew_seconds=max_skew_seconds)
    return ok


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
        timestamp=_iso(_now()),
        nonce=b64u_encode(uuid.uuid4().bytes),
        body_sha256=sha256_hex(body),
        source_manifest_revision=source_manifest_revision,
    )
    data = sign_dict(env.model_dump(exclude_none=True), key, key_id)
    return SignedRequest.model_validate(data)


class NonceCache:
    """In-memory replay guard. Swap for Redis/DB in production."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def check_and_add(self, nonce: str) -> bool:
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        return True


def verify_signed_request(
    env: SignedRequest,
    jwk: JWK,
    *,
    self_node_id: str,
    body: bytes = b"",
    max_skew_seconds: int = 300,
    nonces: NonceCache | None = None,
) -> tuple[bool, str]:
    """Returns (ok, reason). Caller supplies the signer's current JWK."""
    if env.signature is None:
        return False, "unsigned"
    if env.target_node_id != self_node_id:
        return False, "wrong_target"
    if env.body_sha256 != sha256_hex(body):
        return False, "body_mismatch"
    try:
        ts = datetime.fromisoformat(env.timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False, "bad_timestamp"
    if abs((_now() - ts).total_seconds()) > max_skew_seconds:
        return False, "stale_timestamp"
    if nonces is not None and not nonces.check_and_add(env.nonce):
        return False, "replay"
    if not verify_dict(env.model_dump(exclude_none=True), jwk):
        return False, "bad_signature"
    return True, "ok"
