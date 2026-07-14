"""Signed-HTTP invariant lock (pimx-3yq.3).

signed_http is federlet's mandatory baseline peer authentication. Every other
auth method a host adds layers on top of it; none may weaken it. This module is
a self-contained regression harness that pins the FULL rejection vocabulary of
`verify_signed_request` and `verify_peer_request` in one place, plus the
nonce-claim ordering (claim only AFTER the signature verifies, with a TTL equal
to the skew window). If a future change drops or renames a reason, or lets an
unauthenticated request burn a nonce, a test here fails.

Kept separate from test_unit.py on purpose: this is the authoritative matrix,
so it deliberately re-exercises behavior rather than sharing fixtures.
"""

from __future__ import annotations

import pytest

from federlet import (
    SIGNATURE_HEADER,
    UnauthorizedPeerRequest,
    build_signed_manifest,
    verify_peer_request,
    verify_signed_request,
)
from federlet.lowlevel import (
    SignedRequest,
    generate_key,
    public_jwk,
    sha256_hex,
    sign_model,
)

# The complete rejection vocabularies, pinned here so a change is deliberate.
SIGNED_REQUEST_REASONS = frozenset(
    {
        "unsigned",
        "wrong_target",
        "method_mismatch",
        "path_mismatch",
        "body_too_large",
        "body_mismatch",
        "stale_timestamp",
        "bad_signature",
        "replay",
    }
)
PEER_REQUEST_EXTRA_REASONS = frozenset(
    {"missing_signature", "malformed_envelope", "source_mismatch", "unknown_key"}
)

FEDERATION_ID = "example-federation-prod"
SELF_NODE = "node:org-b:prod"
PEER_NODE = "node:org-a:prod"
METHOD = "POST"
PATH = "/federation/v1/operations"
BODY = b'{"x":1}'


class RecordingNonceCache:
    """Captures every claim so ordering and TTL can be asserted."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object, float | None, bool | None]] = []

    async def set(
        self,
        key: str,
        value: object,
        expire: float | None = None,
        exist: bool | None = None,
    ) -> bool:
        self.calls.append((key, value, expire, exist))
        return True


class ClaimOnceNonceCache:
    """Minimal replay-protecting cache: a nonce can be claimed exactly once."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    async def set(
        self,
        key: str,
        value: object,
        expire: float | None = None,
        exist: bool | None = None,
    ) -> bool:
        if exist is False and key in self._seen:
            return False
        self._seen.add(key)
        return True


def _signed_env(key, key_id: str, *, body: bytes = BODY, **overrides) -> SignedRequest:
    """Build a validly-signed SignedRequest, applying field overrides pre-signing."""
    fields: dict[str, object] = {
        "federation_id": FEDERATION_ID,
        "request_id": "req-1",
        "source_node_id": PEER_NODE,
        "target_node_id": SELF_NODE,
        "method": METHOD,
        "path": PATH,
        "timestamp": _now(),
        "nonce": "nonce-1",
        "body_sha256": sha256_hex(body),
        "source_manifest_revision": 0,
    }
    fields.update(overrides)
    return sign_model(SignedRequest(**fields), key, key_id)


def _now():
    from federlet._time import utc_now

    return utc_now()


def _verify(env: SignedRequest, key, *, cache=None, **overrides):
    kwargs: dict[str, object] = {
        "self_node_id": SELF_NODE,
        "method": METHOD,
        "path": PATH,
        "body": BODY,
    }
    kwargs.update(overrides)
    return verify_signed_request(env, public_jwk(key), cache=cache, **kwargs)


# --- verify_signed_request: full rejection matrix -----------------------------


async def test_signed_request_accepts_a_well_formed_envelope():
    key = generate_key()
    assert await _verify(_signed_env(key, "k1"), key) == (True, "ok")


async def test_signed_request_rejects_unsigned_envelope():
    key = generate_key()
    env = _signed_env(key, "k1").model_copy(update={"signature": None})
    assert await _verify(env, key) == (False, "unsigned")


async def test_signed_request_rejects_wrong_target():
    key = generate_key()
    assert await _verify(_signed_env(key, "k1"), key, self_node_id="node:other") == (
        False,
        "wrong_target",
    )


async def test_signed_request_rejects_method_mismatch():
    key = generate_key()
    assert await _verify(_signed_env(key, "k1"), key, method="GET") == (
        False,
        "method_mismatch",
    )


async def test_signed_request_rejects_path_mismatch():
    key = generate_key()
    assert await _verify(_signed_env(key, "k1"), key, path="/other") == (
        False,
        "path_mismatch",
    )


async def test_signed_request_rejects_body_too_large():
    key = generate_key()
    env = _signed_env(key, "k1")
    ok, reason = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id=SELF_NODE,
        method=METHOD,
        path=PATH,
        body=BODY,
        max_body_bytes=1,
    )
    assert (ok, reason) == (False, "body_too_large")


async def test_signed_request_rejects_body_mismatch():
    key = generate_key()
    assert await _verify(_signed_env(key, "k1"), key, body=b"{}") == (
        False,
        "body_mismatch",
    )


async def test_signed_request_rejects_stale_timestamp():
    from datetime import timedelta

    key = generate_key()
    env = _signed_env(key, "k1", timestamp=_now() - timedelta(seconds=3600))
    ok, reason = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id=SELF_NODE,
        method=METHOD,
        path=PATH,
        body=BODY,
        max_skew_seconds=300,
    )
    assert (ok, reason) == (False, "stale_timestamp")


async def test_signed_request_rejects_bad_signature():
    key, attacker = generate_key(), generate_key()
    env = _signed_env(key, "k1")
    assert await _verify(env, attacker) == (False, "bad_signature")


async def test_signed_request_rejects_replay():
    key = generate_key()
    cache = ClaimOnceNonceCache()
    env = _signed_env(key, "k1")
    assert await _verify(env, key, cache=cache) == (True, "ok")
    assert await _verify(env, key, cache=cache) == (False, "replay")


def test_signed_request_reason_vocabulary_is_pinned():
    # A change to the rejection vocabulary must be a deliberate edit here.
    assert SIGNED_REQUEST_REASONS == {
        "unsigned",
        "wrong_target",
        "method_mismatch",
        "path_mismatch",
        "body_too_large",
        "body_mismatch",
        "stale_timestamp",
        "bad_signature",
        "replay",
    }


# --- nonce-claim ordering + TTL ----------------------------------------------


async def test_nonce_is_claimed_only_after_verification_with_skew_ttl():
    key = generate_key()
    cache = RecordingNonceCache()
    env = _signed_env(key, "k1")
    assert await _verify(env, key, cache=cache, max_skew_seconds=120) == (True, "ok")
    # Exactly one claim, TTL == skew window, value 1, exist=False (claim-if-absent).
    assert len(cache.calls) == 1
    key_str, value, expire, exist = cache.calls[0]
    assert value == 1
    assert expire == 120
    assert exist is False
    assert env.nonce in key_str


@pytest.mark.parametrize(
    "overrides",
    [
        {"self_node_id": "node:other"},  # wrong_target
        {"method": "GET"},  # method_mismatch
        {"path": "/other"},  # path_mismatch
        {"body": b"{}"},  # body_mismatch
    ],
)
async def test_pre_verification_rejection_never_burns_a_nonce(overrides):
    key = generate_key()
    cache = RecordingNonceCache()
    ok, _ = await _verify(_signed_env(key, "k1"), key, cache=cache, **overrides)
    assert ok is False
    assert cache.calls == []


async def test_bad_signature_never_burns_a_nonce():
    key, attacker = generate_key(), generate_key()
    cache = RecordingNonceCache()
    ok, reason = await _verify(_signed_env(key, "k1"), attacker, cache=cache)
    assert (ok, reason) == (False, "bad_signature")
    assert cache.calls == []


# --- verify_peer_request: header + envelope selection matrix ------------------


def _peer_manifest(key, key_id: str, *, node_id: str = PEER_NODE):
    return build_signed_manifest(
        key,
        key_id,
        node_id=node_id,
        org_id="org-a",
        endpoint="https://a.example/federation/v1",
        federations=[FEDERATION_ID],
        protocol_versions=["example-federation/1"],
    )


def _header(env: SignedRequest) -> str:
    return env.model_dump_json(exclude_none=True)


async def _verify_peer(header, manifest, *, cache=None):
    return await verify_peer_request(
        signature_header=header,
        peer_manifest=manifest,
        self_node_id=SELF_NODE,
        method=METHOD,
        path=PATH,
        body=BODY,
        cache=cache,
    )


async def test_peer_request_returns_verified_identity():
    key = generate_key()
    manifest = _peer_manifest(key, "k1")
    verified = await _verify_peer(_header(_signed_env(key, "k1")), manifest)
    assert verified.source_node_id == PEER_NODE
    assert verified.key_id == "k1"


async def test_peer_request_rejects_missing_signature_header():
    key = generate_key()
    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await _verify_peer(None, _peer_manifest(key, "k1"))
    assert exc.value.reason == "missing_signature"


async def test_peer_request_rejects_malformed_envelope():
    key = generate_key()
    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await _verify_peer("not-json", _peer_manifest(key, "k1"))
    assert exc.value.reason == "malformed_envelope"


async def test_peer_request_rejects_source_mismatch():
    key = generate_key()
    # Envelope claims PEER_NODE, but the supplied manifest is a different node.
    manifest = _peer_manifest(key, "k1", node_id="node:someone-else:prod")
    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await _verify_peer(_header(_signed_env(key, "k1")), manifest)
    assert exc.value.reason == "source_mismatch"


async def test_peer_request_rejects_unknown_key():
    signer, other = generate_key(), generate_key()
    # Manifest advertises `other`'s key under k1; envelope is signed by `signer`.
    manifest = _peer_manifest(other, "k1")
    env = _signed_env(signer, "k2")
    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await _verify_peer(_header(env), manifest)
    assert exc.value.reason == "unknown_key"


async def test_peer_request_delegates_to_signed_request_checks():
    # A reason from verify_signed_request (here: replay) surfaces through the
    # one-call helper too, proving signed_http checks are not bypassed.
    key = generate_key()
    manifest = _peer_manifest(key, "k1")
    cache = ClaimOnceNonceCache()
    header = _header(_signed_env(key, "k1"))
    await _verify_peer(header, manifest, cache=cache)
    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await _verify_peer(header, manifest, cache=cache)
    assert exc.value.reason == "replay"


def test_signature_header_name_is_stable():
    # Hosts read this header off the inbound request; renaming it is a breaking
    # change to the signed_http baseline.
    assert SIGNATURE_HEADER == "X-Federlet-Signature"
