"""Unit tests for the pure protocol core (no sockets)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cashews import Cache
from pydantic import ValidationError

from pimx import (
    Manifest,
    MemberRecord,
    Membership,
    MembershipTable,
    PeerState,
    PublicKey,
    Query,
    AdmissionPolicy,
    admit_manifest,
    build_signed_request,
    check_manifest,
    domain_evidence_verifier,
    generate_key,
    public_jwk,
    sign_manifest,
    verify_manifest,
    verify_signed_request,
)
from pimx.client import FederationClient, ResponseSignatureError
from pimx.net import SSRFError, _assert_public_host


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


@pytest.fixture
async def cache():
    """A real cashews mem:// backend — same code path as redis/valkey in prod."""
    c = Cache()
    c.setup("mem://")
    yield c
    await c.close()


class RecordingNonceCache:
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


def _manifest(key, key_id="k1", **extra) -> Manifest:
    data = {
        "node_id": "dir:org-a:prod",
        "org_id": "org-a",
        "federations": ["f"],
        "endpoint": "https://dir.org-a.example/federation/v1",
        "revision": 12,
        "public_keys": [PublicKey(key_id=key_id, public_jwk=public_jwk(key))],
        "membership": Membership(introduce_url="https://x/i", members_url="https://x/m"),
    } | extra
    m = Manifest(**data)
    return sign_manifest(m, key, key_id)


def test_manifest_sign_verify_and_tamper():
    key = generate_key()
    m = _manifest(key)
    assert verify_manifest(m)
    assert not verify_manifest(m.model_copy(update={"revision": 999}))


def test_manifest_membership_round_trips_as_typed_model():
    key = generate_key()
    m = _manifest(key)
    assert isinstance(m.membership, Membership)
    assert m.membership.introduce_url == "https://x/i"
    assert m.membership.members_url == "https://x/m"
    wire = m.model_dump(mode="json")
    assert wire["membership"] == {
        "introduce_url": "https://x/i",
        "members_url": "https://x/m",
        "revocations_url": None,
    }
    assert Manifest.model_validate(wire).membership == m.membership


def test_manifest_missing_membership_key_raises_validation_error():
    key = generate_key()
    data = {
        "node_id": "dir:org-a:prod",
        "org_id": "org-a",
        "endpoint": "https://dir.org-a.example/federation/v1",
        "public_keys": [PublicKey(key_id="k1", public_jwk=public_jwk(key))],
        "membership": {"introduce_url": "https://x/i"},  # missing members_url
    }
    with pytest.raises(ValidationError):
        Manifest(**data)


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


def test_manifest_timestamps_normalize_to_z_and_verify():
    key = generate_key()
    # A non-UTC, sub-second timestamp must serialize to canonical UTC 'Z' form
    # and still verify — signatures are computed over the normalized wire bytes.
    aware = datetime(2020, 1, 1, 12, 30, 15, 500_000, tzinfo=timezone(timedelta(hours=2)))
    m = _manifest(key, issued_at=aware, expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    assert verify_manifest(m)
    wire = m.model_dump(mode="json")
    assert wire["issued_at"] == "2020-01-01T10:30:15Z"
    # round-trips through the wire without breaking the signature
    assert verify_manifest(Manifest.model_validate(wire))


async def test_admission_policy_accepts_valid_manifest():
    key = generate_key()
    now = datetime.now(timezone.utc)
    manifest = _manifest(
        key,
        federations=["supplier-network-prod"],
        protocol_versions=["agent-directory-federation/1"],
        endpoint="https://dir.org-a.example/federation/v1",
        auth_methods=["signed_http"],
        admission_evidence={"type": "domain_proof", "domain": "org-a.example"},
        issued_at=_iso(now - timedelta(minutes=1)),
        expires_at=_iso(now + timedelta(days=7)),
    )
    decision = await admit_manifest(
        manifest,
        AdmissionPolicy(
            federation_id="supplier-network-prod",
            protocol_versions={"agent-directory-federation/1"},
            evidence_verifier=domain_evidence_verifier,
        ),
    )
    assert decision.accepted
    assert decision.reason == "ok"


@pytest.mark.parametrize("extra,reason", [
    ({"federations": ["other"]}, "wrong_federation"),
    ({"protocol_versions": ["unknown/1"]}, "unsupported_protocol"),
    ({"auth_methods": ["mtls"]}, "signed_http_required"),
    ({"endpoint": "http://dir.org-a.example/federation/v1"}, "https_required"),
    ({"endpoint": "https://127.0.0.1/federation/v1"}, "private_endpoint_denied"),
])
async def test_admission_policy_rejects_bad_claims(extra, reason):
    key = generate_key()
    now = datetime.now(timezone.utc)
    claims = {
        "federations": ["supplier-network-prod"],
        "protocol_versions": ["agent-directory-federation/1"],
        "auth_methods": ["signed_http"],
        "issued_at": _iso(now - timedelta(minutes=1)),
        "expires_at": _iso(now + timedelta(days=7)),
    } | extra
    manifest = _manifest(key, **claims)
    decision = await admit_manifest(
        manifest,
        AdmissionPolicy(
            federation_id="supplier-network-prod",
            protocol_versions={"agent-directory-federation/1"},
        ),
    )
    assert not decision.accepted
    assert decision.reason == reason


async def test_admission_policy_requires_expiry_by_default():
    key = generate_key()
    manifest = _manifest(
        key,
        federations=["supplier-network-prod"],
        protocol_versions=["agent-directory-federation/1"],
    )
    policy = AdmissionPolicy(
        federation_id="supplier-network-prod",
        protocol_versions={"agent-directory-federation/1"},
    )
    assert (await admit_manifest(manifest, policy)).reason == "missing_expires_at"


async def test_domain_evidence_verifier_rejects_endpoint_outside_domain():
    key = generate_key()
    manifest = _manifest(
        key,
        endpoint="https://dir.evil.example/federation/v1",
        admission_evidence={"type": "domain_proof", "domain": "org-a.example"},
    )
    assert await domain_evidence_verifier(manifest) == (False, "domain_mismatch")


def test_manifest_wrong_key_fails():
    m = _manifest(generate_key())
    # re-sign body with a different key but keep advertised key -> mismatch
    other = _manifest(generate_key())
    forged = m.model_copy(update={"signature": other.signature})
    assert not verify_manifest(forged)


async def test_signed_request_roundtrip_and_replay(cache):
    key = generate_key()
    jwk = public_jwk(key)
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=b'{"x":1}',
    )
    first = await verify_signed_request(env, jwk, self_node_id="b", body=b'{"x":1}', cache=cache)
    assert first == (True, "ok")
    # replay of the same nonce is rejected by the cashews claim
    replay = await verify_signed_request(env, jwk, self_node_id="b", body=b'{"x":1}', cache=cache)
    assert replay == (False, "replay")


async def test_replay_cache_key_is_scoped_to_request_context():
    key = generate_key()
    env = build_signed_request(
        key,
        "k1",
        federation_id="supplier-network-prod",
        source_node_id="dir:org-a:prod",
        target_node_id="dir:org-b:prod",
        method="POST",
        path="/query",
        body=b'{"x":1}',
    )
    cache = RecordingNonceCache()

    result = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="dir:org-b:prod",
        body=b'{"x":1}',
        max_skew_seconds=120,
        cache=cache,
    )

    assert result == (True, "ok")
    assert cache.calls == [(
        f"pimx:nonce:supplier-network-prod:dir:org-a:prod:dir:org-b:prod:{env.nonce}",
        1,
        120,
        False,
    )]


async def test_bad_signature_does_not_burn_the_nonce(cache):
    # An unauthenticated request must not consume a nonce the real signer will
    # later use: the claim happens only after the signature verifies.
    key, attacker = generate_key(), generate_key()
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=b'{"x":1}',
    )
    forged = env.model_copy(update={"nonce": env.nonce})  # same nonce, wrong key below
    bad = await verify_signed_request(
        forged, public_jwk(attacker), self_node_id="b", body=b'{"x":1}', cache=cache
    )
    assert bad == (False, "bad_signature")
    # the genuine request with that nonce still goes through
    ok = await verify_signed_request(env, public_jwk(key), self_node_id="b", body=b'{"x":1}', cache=cache)
    assert ok == (True, "ok")


@pytest.mark.parametrize("kwargs,reason", [
    ({"self_node_id": "b", "body": b"{}"}, "body_mismatch"),
    ({"self_node_id": "wrong", "body": b'{"x":1}'}, "wrong_target"),
])
async def test_signed_request_rejections(kwargs, reason):
    key = generate_key()
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=b'{"x":1}',
    )
    ok, why = await verify_signed_request(env, public_jwk(key), **kwargs)
    assert not ok and why == reason


async def test_query_rejects_unsigned_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key)
    unsigned = {"query_id": "q", "source_node_id": peer.node_id, "results": []}

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=unsigned)

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(ResponseSignatureError):
            await client.query(peer, Query(query_id="q", query={}))
    finally:
        await client.close()


def test_membership_cooldown_and_recovery():
    t = MembershipTable(max_failures=2, base_cooldown=timedelta(seconds=1))
    t.upsert(MemberRecord(node_id="n", manifest_url="https://x/m.json"))
    t.admit(t.get("n"))
    assert [r.node_id for r in t.eligible_peers()] == ["n"]

    t.record_failure("n")
    t.record_failure("n")
    assert t.get("n").state == PeerState.ACTIVE
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
