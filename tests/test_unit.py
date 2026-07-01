"""Unit tests for the pure protocol core (no sockets)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pimx import (
    Manifest,
    MemberRecord,
    MembershipTable,
    NonceCache,
    PeerState,
    PublicKey,
    build_signed_request,
    check_manifest,
    generate_key,
    public_jwk,
    sign_manifest,
    verify_manifest,
    verify_signed_request,
)
from pimx.client import SSRFError, _assert_public_host


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _manifest(key, key_id="k1", **extra) -> Manifest:
    m = Manifest(
        node_id="dir:org-a:prod", org_id="org-a", federations=["f"],
        endpoint="https://dir.org-a.example/federation/v1", revision=12,
        public_keys=[PublicKey(key_id=key_id, public_jwk=public_jwk(key))],
        membership={"introduce_url": "https://x/i", "members_url": "https://x/m"},
        **extra,
    )
    return sign_manifest(m, key, key_id)


def test_manifest_sign_verify_and_tamper():
    key = generate_key()
    m = _manifest(key)
    assert verify_manifest(m)
    assert not verify_manifest(m.model_copy(update={"revision": 999}))


def test_manifest_freshness_is_enforced():
    key = generate_key()
    now = datetime.now(timezone.utc)

    fresh = _manifest(
        key, issued_at=_iso(now - timedelta(hours=1)),
        expires_at=_iso(now + timedelta(days=7)),
    )
    assert check_manifest(fresh) == (True, "ok")
    assert verify_manifest(fresh)

    expired = _manifest(
        key, issued_at=_iso(now - timedelta(days=8)),
        expires_at=_iso(now - timedelta(days=1)),
    )
    assert check_manifest(expired) == (False, "expired")
    assert not verify_manifest(expired)

    future = _manifest(key, issued_at=_iso(now + timedelta(hours=1)))
    assert check_manifest(future) == (False, "not_yet_valid")

    # no timestamps -> freshness is not judged; signature alone governs
    assert check_manifest(_manifest(key)) == (True, "ok")


def test_manifest_wrong_key_fails():
    m = _manifest(generate_key())
    # re-sign body with a different key but keep advertised key -> mismatch
    other = _manifest(generate_key())
    forged = m.model_copy(update={"signature": other.signature})
    assert not verify_manifest(forged)


def test_signed_request_roundtrip_and_replay():
    key = generate_key()
    jwk = public_jwk(key)
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=b'{"x":1}',
    )
    nonces = NonceCache()
    assert verify_signed_request(env, jwk, self_node_id="b", body=b'{"x":1}', nonces=nonces) == (True, "ok")
    # replay of the same nonce
    assert verify_signed_request(env, jwk, self_node_id="b", body=b'{"x":1}', nonces=nonces) == (False, "replay")


@pytest.mark.parametrize("kwargs,reason", [
    ({"self_node_id": "b", "body": b"{}"}, "body_mismatch"),
    ({"self_node_id": "wrong", "body": b'{"x":1}'}, "wrong_target"),
])
def test_signed_request_rejections(kwargs, reason):
    key = generate_key()
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=b'{"x":1}',
    )
    ok, why = verify_signed_request(env, public_jwk(key), **kwargs)
    assert not ok and why == reason


def test_membership_cooldown_and_recovery():
    t = MembershipTable(max_failures=2, base_cooldown=timedelta(seconds=1))
    t.upsert(MemberRecord(node_id="n", manifest_url="https://x/m.json"))
    t.admit(t.get("n"))
    assert [r.node_id for r in t.eligible_peers()] == ["n"]

    t.record_failure("n")
    t.record_failure("n")
    assert t.get("n").state == PeerState.COOLDOWN
    assert t.eligible_peers() == []  # in cooldown -> not queried

    t.record_success("n")
    assert t.get("n").state == PeerState.ACTIVE
    assert len(t.eligible_peers()) == 1


def test_revoked_peer_is_never_eligible():
    t = MembershipTable()
    t.upsert(MemberRecord(node_id="n", manifest_url="https://x/m.json"))
    t.admit(t.get("n"))
    t.revoke("n")
    assert t.get("n").state == PeerState.REVOKED
    assert t.eligible_peers() == []


def test_ssrf_guard_blocks_private_hosts():
    with pytest.raises(SSRFError):
        _assert_public_host("https://localhost/x")
    with pytest.raises(SSRFError):
        _assert_public_host("http://127.0.0.1:8080/m.json")
    # explicit opt-in bypasses the check (used for local integration tests)
    _assert_public_host("http://127.0.0.1/x", allow_private=True)
