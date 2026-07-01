"""Ed25519 keys, JWK conversion, canonical bytes, and detached signing."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

JWK = dict[str, str]


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_jwk(key: Ed25519PrivateKey | Ed25519PublicKey) -> JWK:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    from cryptography.hazmat.primitives import serialization

    raw = pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": b64u_encode(raw)}


def public_key_from_jwk(jwk: JWK) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("unsupported JWK; expected OKP/Ed25519")
    return Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, compact separators."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def sign_bytes(key: Ed25519PrivateKey, data: bytes) -> str:
    return b64u_encode(key.sign(data))


def verify_bytes(jwk: JWK, sig: str, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        public_key_from_jwk(jwk).verify(b64u_decode(sig), data)
        return True
    except (InvalidSignature, ValueError):
        return False
