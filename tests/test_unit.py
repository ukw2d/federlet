"""Unit tests for the pure protocol core (no sockets)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cashews import Cache
from pydantic import ValidationError

from pimx import (
    AdmissionEvidence,
    CapabilitySummary,
    JWK,
    Disclosure,
    DomainProofEvidence,
    GenericAdmissionEvidence,
    HealthResponse,
    IntroduceRequest,
    IntroduceResponse,
    Manifest,
    ManifestVerificationError,
    ManifestLimits,
    ManifestRefreshDecision,
    MemberRecord,
    MembersResponse,
    Membership,
    MembershipStore,
    MembershipTable,
    MissingCapabilitySummaryEndpointError,
    MissingRevocationsEndpointError,
    PeerState,
    PeerHealthProbeResult,
    ProtocolResponse,
    PublicKey,
    RateLimiter,
    RevocationNotice,
    RevocationsResponse,
    ResponseSignatureError,
    SIGNATURE_HEADER,
    AdmissionPolicy,
    DisclosurePolicy,
    admit_manifest,
    apply_revocation_notice,
    audit_record,
    b64u_decode,
    b64u_encode,
    build_signed_request,
    canonical_bytes,
    check_body_size,
    check_key_continuity,
    check_manifest,
    domain_evidence_verifier,
    generate_key,
    KeyContinuityPolicy,
    public_jwk,
    public_key_from_jwk,
    probe_peer_health,
    refresh_peer_manifest,
    sha256_hex,
    sign_model,
    sign_manifest,
    TokenBucketRateLimiter,
    disclose_members,
    verify_manifest,
    verify_model,
    verify_response_signature,
    verify_revocation_notice,
    verify_signed_request,
)
from pimx.client import FederationClient
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


def test_manifest_optional_disclosure_limits_and_capability_summary_round_trip():
    key = generate_key()
    m = _manifest(
        key,
        capability_summary_url="https://x/capability-summary",
        disclosure={"default": "federation", "supports_partner_scopes": True},
        limits={
            "max_query_rps_per_peer": 3,
            "max_query_timeout_ms": 500,
            "max_results": 25,
        },
    )
    assert isinstance(m.disclosure, Disclosure)
    assert isinstance(m.limits, ManifestLimits)
    assert verify_manifest(m)

    wire = m.model_dump(mode="json")
    assert wire["capability_summary_url"] == "https://x/capability-summary"
    assert wire["disclosure"] == {
        "default": "federation",
        "supports_partner_scopes": True,
    }
    assert wire["limits"] == {
        "max_query_rps_per_peer": 3,
        "max_query_timeout_ms": 500,
        "max_results": 25,
    }
    assert verify_manifest(Manifest.model_validate(wire))


def test_manifest_extension_fields_remain_optional():
    key = generate_key()
    m = _manifest(key)
    wire = m.model_dump(mode="json")
    assert wire["capability_summary_url"] is None
    assert wire["disclosure"] is None
    assert wire["limits"] is None
    assert Manifest.model_validate(wire).disclosure is None
    assert Manifest.model_validate(wire).limits is None


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


def test_introduce_response_accepted_until_round_trips_as_aware_datetime():
    # accepted_until is an AwareDatetime that serializes to ISO-Z, mirroring
    # IntroduceRequest.timestamp. ADR-005 §8.2.
    until = datetime(2026, 7, 8, 10, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    resp = IntroduceResponse(accepted=True, accepted_until=until, known_peer_count=14)
    wire = resp.model_dump(mode="json")
    assert wire["accepted_until"] == "2026-07-08T08:00:00Z"
    assert wire["known_peer_count"] == 14
    rt = IntroduceResponse.model_validate(wire)
    assert rt.accepted_until == datetime(2026, 7, 8, 8, 0, 0, tzinfo=timezone.utc)
    assert rt.known_peer_count == 14

    # None stays None on the wire (no spurious empty string).
    assert IntroduceResponse(accepted=True).model_dump(mode="json")["accepted_until"] is None


def test_manifest_domain_proof_admission_evidence_round_trips_as_typed_model():
    key = generate_key()
    manifest = _manifest(
        key,
        admission_evidence={"type": "domain_proof", "domain": "org-a.example"},
    )

    assert isinstance(manifest.admission_evidence, DomainProofEvidence)
    evidence = manifest.admission_evidence
    assert evidence.domain == "org-a.example"
    wire = manifest.model_dump(mode="json")
    assert wire["admission_evidence"] == {
        "type": "domain_proof",
        "domain": "org-a.example",
    }
    assert isinstance(Manifest.model_validate(wire).admission_evidence, DomainProofEvidence)


def test_manifest_unknown_admission_evidence_keeps_tagged_shape():
    key = generate_key()
    manifest = _manifest(
        key,
        admission_evidence={"type": "spiffe", "trust_domain": "example.org"},
    )

    assert isinstance(manifest.admission_evidence, GenericAdmissionEvidence)
    wire = manifest.model_dump(mode="json")
    assert wire["admission_evidence"] == {
        "type": "spiffe",
        "trust_domain": "example.org",
    }


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


async def test_key_continuity_accepts_no_key_change():
    key = generate_key()
    old_manifest = _manifest(key, key_id="org-a-k1", revision=12)
    new_manifest = _manifest(key, key_id="org-a-k1", revision=13)

    decision = await check_key_continuity(old_manifest, new_manifest)

    assert decision.action == "accept"
    assert decision.reason == "ok"


async def test_key_continuity_accepts_rotation_signed_by_old_key():
    old_key, new_key = generate_key(), generate_key()
    old_manifest = _manifest(old_key, key_id="org-a-k1", revision=12)
    new_manifest = _manifest(
        old_key,
        key_id="org-a-k1",
        revision=13,
        public_keys=[
            PublicKey(key_id="org-a-k1", public_jwk=public_jwk(old_key)),
            PublicKey(key_id="org-a-k2", public_jwk=public_jwk(new_key)),
        ],
    )

    decision = await check_key_continuity(old_manifest, new_manifest)

    assert decision.action == "accept"
    assert decision.reason == "signed_rotation"


async def test_key_continuity_quarantines_unauthorized_rotation():
    old_key, new_key = generate_key(), generate_key()
    old_manifest = _manifest(old_key, key_id="org-a-k1", revision=12)
    new_manifest = _manifest(new_key, key_id="org-a-k2", revision=13)

    decision = await check_key_continuity(old_manifest, new_manifest)

    assert decision.action == "quarantine"
    assert decision.reason == "stale_manifest"


async def test_key_continuity_accepts_evidence_authorized_rotation():
    async def evidence_verifier(manifest: Manifest) -> tuple[bool, str]:
        assert manifest.admission_evidence is not None
        return True, "ok"

    old_key, new_key = generate_key(), generate_key()
    old_manifest = _manifest(old_key, key_id="org-a-k1", revision=12)
    new_manifest = _manifest(
        new_key,
        key_id="org-a-k2",
        revision=13,
        admission_evidence={"type": "domain_proof", "domain": "org-a.example"},
    )

    decision = await check_key_continuity(
        old_manifest,
        new_manifest,
        KeyContinuityPolicy(evidence_verifier=evidence_verifier),
    )

    assert decision.action == "accept"
    assert decision.reason == "admission_evidence"


async def test_key_continuity_rejects_when_local_policy_denies_rotation():
    old_key, new_key = generate_key(), generate_key()
    old_manifest = _manifest(old_key, key_id="org-a-k1", revision=12)
    new_manifest = _manifest(new_key, key_id="org-a-k2", revision=13)

    decision = await check_key_continuity(
        old_manifest,
        new_manifest,
        KeyContinuityPolicy(allow_key_rotation=False),
    )

    assert decision.action == "reject"
    assert decision.reason == "rotation_denied"


def test_manifest_wrong_key_fails():
    m = _manifest(generate_key())
    # re-sign body with a different key but keep advertised key -> mismatch
    other = _manifest(generate_key())
    forged = m.model_copy(update={"signature": other.signature})
    assert not verify_manifest(forged)


def test_verify_response_signature_accepts_peer_signed_response():
    peer_key = generate_key()
    peer = _manifest(peer_key)
    signed = sign_model(
        IntroduceResponse(accepted=True, accepted_node_id=peer.node_id),
        peer_key,
        "k1",
    )

    assert verify_response_signature(peer, signed)
    assert not verify_response_signature(peer, signed.model_copy(update={"signature": None}))


def test_revocation_notice_round_trips_and_verifies():
    key = generate_key()
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="dir:org-b:prod",
            reason="removed",
            issued_at=datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 7, 10, 10, 0, tzinfo=timezone.utc),
            issuer="dir:org-a:prod",
        ),
        key,
        "k1",
    )

    wire = notice.model_dump(mode="json")
    assert wire["issued_at"] == "2026-07-09T10:00:00Z"
    assert wire["expires_at"] == "2026-07-10T10:00:00Z"
    assert verify_revocation_notice(RevocationNotice.model_validate(wire), public_jwk(key))
    assert RevocationsResponse(source_node_id="dir:org-a:prod", notices=[notice])


def test_capability_summary_round_trips_and_verifies():
    key = generate_key()
    summary = sign_model(
        CapabilitySummary(
            node_id="dir:org-a:prod",
            summary_version=1,
            record_types=["supplier"],
            domains=["manufacturing"],
            skills_top=["cnc"],
            coverage_text="Supplier catalogue",
            updated_at=datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 7, 10, 10, 0, tzinfo=timezone.utc),
        ),
        key,
        "k1",
    )

    wire = summary.model_dump(mode="json")
    assert wire["updated_at"] == "2026-07-09T10:00:00Z"
    assert wire["expires_at"] == "2026-07-10T10:00:00Z"
    assert CapabilitySummary.model_validate(wire) == summary
    assert verify_model(summary, public_jwk(key))


def test_token_bucket_rate_limiter_allows_up_to_peer_manifest_rate():
    limiter: RateLimiter = TokenBucketRateLimiter({
        "dir:org-a:prod": ManifestLimits(max_query_rps_per_peer=2),
    })

    assert limiter.allow("dir:org-a:prod", now=0.0)
    assert limiter.allow("dir:org-a:prod", now=0.0)
    assert not limiter.allow("dir:org-a:prod", now=0.0)


def test_token_bucket_rate_limiter_refills_over_time():
    limiter = TokenBucketRateLimiter({
        "dir:org-a:prod": ManifestLimits(max_query_rps_per_peer=2),
    })

    assert limiter.allow("dir:org-a:prod", now=0.0)
    assert limiter.allow("dir:org-a:prod", now=0.0)
    assert not limiter.allow("dir:org-a:prod", now=0.25)
    assert limiter.allow("dir:org-a:prod", now=0.5)
    assert not limiter.allow("dir:org-a:prod", now=0.5)


def test_token_bucket_rate_limiter_treats_missing_limit_as_unbounded():
    limiter = TokenBucketRateLimiter({
        "dir:org-a:prod": ManifestLimits(),
    })

    assert limiter.allow("unknown", now=0.0)
    assert limiter.allow("dir:org-a:prod", now=0.0)
    assert limiter.allow("dir:org-a:prod", now=0.0)


async def test_signed_request_roundtrip_and_replay(cache):
    key = generate_key()
    jwk = public_jwk(key)
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=b'{"x":1}',
    )
    first = await verify_signed_request(
        env,
        jwk,
        self_node_id="b",
        method="POST",
        path="/query",
        body=b'{"x":1}',
        cache=cache,
    )
    assert first == (True, "ok")
    # replay of the same nonce is rejected by the cashews claim
    replay = await verify_signed_request(
        env,
        jwk,
        self_node_id="b",
        method="POST",
        path="/query",
        body=b'{"x":1}',
        cache=cache,
    )
    assert replay == (False, "replay")


async def test_signed_request_body_size_limit_passes_under_limit(cache):
    key = generate_key()
    body = b'{"x":1}'
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=body,
    )

    assert check_body_size(body, len(body))
    assert await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="b",
        method="POST",
        path="/query",
        body=body,
        max_body_bytes=len(body),
        cache=cache,
    ) == (True, "ok")


async def test_signed_request_body_size_limit_rejects_without_burning_nonce(cache):
    key = generate_key()
    body = b'{"payload":"too-large"}'
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=body,
    )

    assert not check_body_size(body, len(body) - 1)
    oversized = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="b",
        method="POST",
        path="/query",
        body=body,
        max_body_bytes=len(body) - 1,
        cache=cache,
    )
    assert oversized == (False, "body_too_large")

    ok = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="b",
        method="POST",
        path="/query",
        body=body,
        cache=cache,
    )
    assert ok == (True, "ok")


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
        method="POST",
        path="/query",
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
        forged,
        public_jwk(attacker),
        self_node_id="b",
        method="POST",
        path="/query",
        body=b'{"x":1}',
        cache=cache,
    )
    assert bad == (False, "bad_signature")
    # the genuine request with that nonce still goes through
    ok = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="b",
        method="POST",
        path="/query",
        body=b'{"x":1}',
        cache=cache,
    )
    assert ok == (True, "ok")


@pytest.mark.parametrize("kwargs,reason", [
    ({"self_node_id": "b", "method": "POST", "path": "/query", "body": b"{}"}, "body_mismatch"),
    ({"self_node_id": "wrong", "method": "POST", "path": "/query", "body": b'{"x":1}'}, "wrong_target"),
    ({"self_node_id": "b", "method": "GET", "path": "/query", "body": b'{"x":1}'}, "method_mismatch"),
    ({"self_node_id": "b", "method": "POST", "path": "/other", "body": b'{"x":1}'}, "path_mismatch"),
])
async def test_signed_request_rejections(kwargs, reason):
    key = generate_key()
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=b'{"x":1}',
    )
    ok, why = await verify_signed_request(env, public_jwk(key), **kwargs)
    assert not ok and why == reason


async def test_method_path_mismatch_does_not_burn_nonce(cache):
    key = generate_key()
    env = build_signed_request(
        key, "k1", federation_id="f", source_node_id="a", target_node_id="b",
        method="POST", path="/query", body=b'{"x":1}',
    )

    bad = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="b",
        method="POST",
        path="/other",
        body=b'{"x":1}',
        cache=cache,
    )
    assert bad == (False, "path_mismatch")

    ok = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="b",
        method="POST",
        path="/query",
        body=b'{"x":1}',
        cache=cache,
    )
    assert ok == (True, "ok")


async def test_members_rejects_unsigned_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key)
    unsigned = {"source_node_id": peer.node_id, "members": []}

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
            await client.get_members(peer)
    finally:
        await client.close()


async def test_members_accepts_signed_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key)
    signed = sign_model(MembersResponse(source_node_id=peer.node_id), peer_key, "k1")

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=signed.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        assert await client.get_members(peer) == signed
    finally:
        await client.close()


async def test_get_revocations_accepts_signed_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(
        peer_key,
        membership=Membership(
            introduce_url="https://x/i",
            members_url="https://x/m",
            revocations_url="https://x/r",
        ),
    )
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="dir:org-b:prod",
            reason="removed",
            issued_at=datetime.now(timezone.utc),
            issuer=peer.node_id,
        ),
        peer_key,
        "k1",
    )
    signed = sign_model(
        RevocationsResponse(source_node_id=peer.node_id, notices=[notice]),
        peer_key,
        "k1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/r"
        assert request.url.params["since"] == "cursor-1"
        return httpx.Response(200, json=signed.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        assert await client.get_revocations(peer, since="cursor-1") == signed
    finally:
        await client.close()


@pytest.mark.parametrize("response_factory", [
    lambda peer, _: RevocationsResponse(source_node_id=peer.node_id),
    lambda peer, bad_key: sign_model(
        RevocationsResponse(source_node_id=peer.node_id),
        bad_key,
        "k1",
    ),
])
async def test_get_revocations_rejects_unsigned_or_bad_response(response_factory):
    import httpx

    peer_key = generate_key()
    peer = _manifest(
        peer_key,
        membership=Membership(
            introduce_url="https://x/i",
            members_url="https://x/m",
            revocations_url="https://x/r",
        ),
    )
    response = response_factory(peer, generate_key())

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(ResponseSignatureError):
            await client.get_revocations(peer)
    finally:
        await client.close()


async def test_get_revocations_requires_advertised_endpoint():
    import httpx

    peer = _manifest(generate_key())

    async def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("request should not be sent")

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(MissingRevocationsEndpointError, match="missing_revocations_url"):
            await client.get_revocations(peer)
    finally:
        await client.close()


async def test_get_capability_summary_accepts_signed_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key, capability_summary_url="https://x/capability")
    signed = sign_model(
        CapabilitySummary(
            node_id=peer.node_id,
            summary_version=1,
            record_types=["supplier"],
            domains=["manufacturing"],
            skills_top=["cnc"],
            coverage_text="Supplier catalogue",
            updated_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ),
        peer_key,
        "k1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/capability"
        return httpx.Response(200, json=signed.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        assert await client.get_capability_summary(peer) == signed
    finally:
        await client.close()


@pytest.mark.parametrize("response_factory", [
    lambda peer, _: CapabilitySummary(
        node_id=peer.node_id,
        summary_version=1,
        coverage_text="Supplier catalogue",
        updated_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    ),
    lambda peer, bad_key: sign_model(
        CapabilitySummary(
            node_id=peer.node_id,
            summary_version=1,
            coverage_text="Supplier catalogue",
            updated_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ),
        bad_key,
        "k1",
    ),
])
async def test_get_capability_summary_rejects_unsigned_or_bad_response(response_factory):
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key, capability_summary_url="https://x/capability")
    response = response_factory(peer, generate_key())

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(ResponseSignatureError):
            await client.get_capability_summary(peer)
    finally:
        await client.close()


async def test_get_capability_summary_requires_advertised_endpoint():
    import httpx

    peer = _manifest(generate_key())

    async def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("request should not be sent")

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(
            MissingCapabilitySummaryEndpointError,
            match="missing_capability_summary_url",
        ):
            await client.get_capability_summary(peer)
    finally:
        await client.close()


async def test_get_protocol_returns_parsed_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key)
    payload = {
        "node_id": peer.node_id,
        "manifest_revision": peer.revision,
        "protocol_versions": ["agent-directory-federation/1"],
        "auth_methods": ["signed_http"],
        "limits": {"max_query_timeout_ms": 500},
        "extra": "host-owned",
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/federation/v1/protocol"
        assert request.headers.get(SIGNATURE_HEADER)
        return httpx.Response(200, json=payload)

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        resp = await client.get_protocol(peer)
    finally:
        await client.close()

    assert isinstance(resp, ProtocolResponse)
    assert resp.node_id == peer.node_id
    assert resp.manifest_revision == peer.revision
    assert resp.protocol_versions == ["agent-directory-federation/1"]
    assert resp.auth_methods == ["signed_http"]
    assert resp.limits is not None
    assert resp.limits.max_query_timeout_ms == 500
    assert resp.model_extra == {"extra": "host-owned"}


async def test_get_health_returns_parsed_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/federation/v1/health"
        assert request.headers.get(SIGNATURE_HEADER)
        return httpx.Response(200, json={"node_id": peer.node_id, "status": "ok"})

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        resp = await client.get_health(peer)
    finally:
        await client.close()

    assert isinstance(resp, HealthResponse)
    assert resp.node_id == peer.node_id
    assert resp.status == "ok"


@pytest.mark.parametrize("method", ["get_protocol", "get_health"])
async def test_probe_helpers_raise_on_unreachable_peer(method):
    import httpx

    peer = _manifest(generate_key())

    async def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unreachable")

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(httpx.ConnectError, match="unreachable"):
            await getattr(client, method)(peer)
    finally:
        await client.close()


async def test_probe_peer_health_classifies_success():
    import httpx

    peer = _manifest(generate_key())

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/protocol"):
            return httpx.Response(200, json={
                "node_id": peer.node_id,
                "protocol_versions": ["agent-directory-federation/1"],
            })
        if request.url.path.endswith("/health"):
            return httpx.Response(200, json={"node_id": peer.node_id, "status": "ok"})
        return httpx.Response(404, json={"error": "not_found"})

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        result = await probe_peer_health(client, peer)
    finally:
        await client.close()

    assert isinstance(result, PeerHealthProbeResult)
    assert result.healthy
    assert result.reason == "ok"
    assert result.suggested_state == PeerState.ACTIVE
    assert result.protocol is not None
    assert result.protocol.node_id == peer.node_id
    assert result.health is not None
    assert result.health.status == "ok"


async def test_probe_peer_health_classifies_protocol_failure():
    import httpx

    peer = _manifest(generate_key())

    async def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("protocol unreachable")

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        result = await probe_peer_health(client, peer)
    finally:
        await client.close()

    assert not result.healthy
    assert result.reason == "protocol_probe_failed"
    assert result.suggested_state == PeerState.COOLDOWN
    assert result.protocol is None
    assert result.health is None
    assert result.error == "protocol unreachable"


async def test_probe_peer_health_classifies_health_failure():
    import httpx

    peer = _manifest(generate_key())

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/protocol"):
            return httpx.Response(200, json={"protocol_versions": ["agent-directory-federation/1"]})
        raise httpx.ConnectError("health unreachable")

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        result = await probe_peer_health(client, peer)
    finally:
        await client.close()

    assert not result.healthy
    assert result.reason == "health_probe_failed"
    assert result.suggested_state == PeerState.COOLDOWN
    assert result.protocol is not None
    assert result.health is None
    assert result.error == "health unreachable"


async def test_probe_peer_health_classifies_unhealthy_status():
    import httpx

    peer = _manifest(generate_key())

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/protocol"):
            return httpx.Response(200, json={"protocol_versions": ["agent-directory-federation/1"]})
        return httpx.Response(200, json={"node_id": peer.node_id, "status": "degraded"})

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        result = await probe_peer_health(client, peer)
    finally:
        await client.close()

    assert not result.healthy
    assert result.reason == "unhealthy"
    assert result.suggested_state == PeerState.COOLDOWN
    assert result.protocol is not None
    assert result.health is not None
    assert result.health.status == "degraded"


async def test_introduce_rejects_bad_signature_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key)
    bad_key = generate_key()
    signed = sign_model(
        IntroduceResponse(accepted=True, accepted_node_id=peer.node_id),
        bad_key,
        "k1",
    )

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=signed.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        intro = IntroduceRequest(
            federation_id="f",
            manifest_url="https://caller.example/.well-known/agent-directory.json",
            manifest=peer,
            nonce="n",
            timestamp=datetime.now(timezone.utc),
        )
        with pytest.raises(ResponseSignatureError):
            await client.introduce(peer, intro)
    finally:
        await client.close()


async def test_fetch_manifest_verifies_signature():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=peer.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        assert await client.fetch_manifest("http://127.0.0.1/manifest.json") == peer
    finally:
        await client.close()


@pytest.mark.parametrize("manifest_update,reason", [
    ({"signature": None}, "unsigned"),
    ({"revision": 999}, "bad_signature"),
])
async def test_fetch_manifest_rejects_unverified_manifest(manifest_update, reason):
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key).model_copy(update=manifest_update)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=peer.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(ManifestVerificationError, match=reason):
            await client.fetch_manifest("http://127.0.0.1/manifest.json")
    finally:
        await client.close()


async def test_refresh_peer_manifest_returns_unchanged_for_same_revision():
    import httpx

    peer_key = generate_key()
    current = _manifest(peer_key, revision=12)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=current.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decision = await refresh_peer_manifest(
            client,
            current,
            "http://127.0.0.1/manifest.json",
        )
    finally:
        await client.close()

    assert isinstance(decision, ManifestRefreshDecision)
    assert decision.action == "unchanged"
    assert decision.reason == "ok"
    assert decision.old_revision == 12
    assert decision.new_revision == 12
    assert decision.manifest == current


async def test_refresh_peer_manifest_accepts_revision_bump():
    import httpx

    peer_key = generate_key()
    current = _manifest(peer_key, revision=12)
    refreshed = _manifest(peer_key, revision=13)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=refreshed.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decision = await refresh_peer_manifest(
            client,
            current,
            "http://127.0.0.1/manifest.json",
        )
    finally:
        await client.close()

    assert decision.action == "accept"
    assert decision.reason == "revision_bump"
    assert decision.old_revision == 12
    assert decision.new_revision == 13
    assert decision.manifest == refreshed
    assert decision.key_continuity is not None
    assert decision.key_continuity.action == "accept"


async def test_refresh_peer_manifest_quarantines_expired_manifest():
    import httpx

    peer_key = generate_key()
    now = datetime.now(timezone.utc)
    current = _manifest(peer_key, revision=12)
    expired = _manifest(
        peer_key,
        revision=13,
        issued_at=_iso(now - timedelta(days=8)),
        expires_at=_iso(now - timedelta(days=1)),
    )

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=expired.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decision = await refresh_peer_manifest(
            client,
            current,
            "http://127.0.0.1/manifest.json",
        )
    finally:
        await client.close()

    assert decision.action == "quarantine"
    assert decision.reason == "stale_manifest"
    assert decision.old_revision == 12
    assert decision.new_revision is None
    assert decision.manifest is None


async def test_refresh_peer_manifest_accepts_old_key_signed_rotation():
    import httpx

    old_key, new_key = generate_key(), generate_key()
    current = _manifest(old_key, key_id="org-a-k1", revision=12)
    refreshed = _manifest(
        old_key,
        key_id="org-a-k1",
        revision=13,
        public_keys=[
            PublicKey(key_id="org-a-k1", public_jwk=public_jwk(old_key)),
            PublicKey(key_id="org-a-k2", public_jwk=public_jwk(new_key)),
        ],
    )

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=refreshed.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decision = await refresh_peer_manifest(
            client,
            current,
            "http://127.0.0.1/manifest.json",
        )
    finally:
        await client.close()

    assert decision.action == "accept"
    assert decision.reason == "revision_bump"
    assert decision.key_continuity is not None
    assert decision.key_continuity.reason == "signed_rotation"


async def test_refresh_peer_manifest_quarantines_unauthorized_rotation():
    import httpx

    old_key, new_key = generate_key(), generate_key()
    current = _manifest(old_key, key_id="org-a-k1", revision=12)
    refreshed = _manifest(new_key, key_id="org-a-k2", revision=13)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=refreshed.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decision = await refresh_peer_manifest(
            client,
            current,
            "http://127.0.0.1/manifest.json",
        )
    finally:
        await client.close()

    assert decision.action == "quarantine"
    assert decision.reason == "stale_manifest"
    assert decision.manifest == refreshed
    assert decision.key_continuity is not None
    assert decision.key_continuity.action == "quarantine"


async def test_refresh_peer_manifest_rejects_rotation_when_policy_denies():
    import httpx

    old_key, new_key = generate_key(), generate_key()
    current = _manifest(old_key, key_id="org-a-k1", revision=12)
    refreshed = _manifest(new_key, key_id="org-a-k2", revision=13)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=refreshed.model_dump(mode="json", exclude_none=True))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decision = await refresh_peer_manifest(
            client,
            current,
            "http://127.0.0.1/manifest.json",
            key_continuity_policy=KeyContinuityPolicy(allow_key_rotation=False),
        )
    finally:
        await client.close()

    assert decision.action == "reject"
    assert decision.reason == "rotation_denied"
    assert decision.key_continuity is not None
    assert decision.key_continuity.action == "reject"


def test_public_crypto_and_signing_helpers_are_exported():
    key = generate_key()
    jwk: JWK = public_jwk(key)
    assert AdmissionEvidence is not None
    assert public_key_from_jwk(jwk)
    assert b64u_decode(b64u_encode(b"abc")) == b"abc"
    assert canonical_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert sha256_hex(b"abc").startswith("sha256:")
    assert SIGNATURE_HEADER == "X-PIMX-Signature"


def test_audit_record_includes_required_shape_and_timestamp():
    record = audit_record(
        event="admission_decision",
        request_id="req-1",
        source_node_id="dir:org-a:prod",
        target_node_id="dir:org-b:prod",
        manifest_revision=7,
        decision="accepted",
        reason="ok",
        extra={"transport": "http", "omitted": None},
    )

    assert record["event"] == "admission_decision"
    assert record["request_id"] == "req-1"
    assert record["source_node_id"] == "dir:org-a:prod"
    assert record["target_node_id"] == "dir:org-b:prod"
    assert record["manifest_revision"] == 7
    assert record["decision"] == "accepted"
    assert record["reason"] == "ok"
    assert record["transport"] == "http"
    assert "omitted" not in record
    assert record["timestamp"].endswith("Z")
    datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))


def test_audit_record_omits_none_optional_fields():
    record = audit_record(event="query")

    assert record["event"] == "query"
    assert "request_id" not in record
    assert "query_id" not in record
    assert "decision" not in record


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


def test_membership_table_satisfies_membership_store_protocol():
    table = MembershipTable()
    store: MembershipStore = table
    assert store is table


def test_disclose_members_excludes_ineligible_and_denied_peers():
    active = MemberRecord(
        node_id="dir:org-a:prod",
        org_id="org-a",
        manifest_url="https://a.example/.well-known/agent-directory.json",
        manifest_revision=2,
    )
    revoked = MemberRecord(
        node_id="dir:org-b:prod",
        manifest_url="https://b.example/.well-known/agent-directory.json",
        state=PeerState.REVOKED,
    )
    denied = MemberRecord(
        node_id="dir:org-c:prod",
        manifest_url="https://c.example/.well-known/agent-directory.json",
    )

    refs = disclose_members(
        [active, revoked, denied],
        requester_node_id="dir:requester:prod",
        policy=DisclosurePolicy(default="federation", denied={"dir:org-c:prod"}),
    )

    assert len(refs) == 1
    assert refs[0].node_id == "dir:org-a:prod"
    assert refs[0].org_id == "org-a"
    assert refs[0].manifest_revision == 2
    assert refs[0].disclosure == "federation"


def test_disclose_members_applies_requester_specific_disclosure():
    rec = MemberRecord(
        node_id="dir:org-a:prod",
        manifest_url="https://a.example/.well-known/agent-directory.json",
    )

    refs = disclose_members(
        [rec],
        requester_node_id="dir:requester:prod",
        policy=DisclosurePolicy(
            default="federation",
            requester_disclosure={"dir:requester:prod": "partner"},
        ),
    )

    assert refs[0].disclosure == "partner"


def test_revoked_peer_is_never_eligible():
    t = MembershipTable()
    t.upsert(MemberRecord(node_id="n", manifest_url="https://x/m.json"))
    t.admit(t.get("n"))
    t.revoke("n")
    assert t.get("n").state == PeerState.REVOKED
    assert t.eligible_peers() == []


def test_apply_revocation_notice_revokes_known_peer_from_trusted_issuer():
    issuer_key = generate_key()
    table = MembershipTable()
    table.admit(MemberRecord(node_id="dir:org-b:prod", manifest_url="https://x/m.json"))
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="dir:org-b:prod",
            reason="removed",
            issued_at=datetime.now(timezone.utc),
            issuer="dir:org-a:prod",
        ),
        issuer_key,
        "issuer-k1",
    )

    state = apply_revocation_notice(
        table,
        notice,
        federation_id="f",
        trusted_issuer_keys={"issuer-k1": public_jwk(issuer_key)},
    )

    assert state == PeerState.REVOKED
    assert table.get("dir:org-b:prod").state == PeerState.REVOKED


def test_apply_revocation_notice_ignores_untrusted_issuer():
    issuer_key = generate_key()
    table = MembershipTable()
    table.admit(MemberRecord(node_id="dir:org-b:prod", manifest_url="https://x/m.json"))
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="dir:org-b:prod",
            reason="removed",
            issued_at=datetime.now(timezone.utc),
            issuer="dir:org-a:prod",
        ),
        issuer_key,
        "issuer-k1",
    )

    state = apply_revocation_notice(
        table,
        notice,
        federation_id="f",
        trusted_issuer_keys={},
    )

    assert state == PeerState.ACTIVE
    assert table.get("dir:org-b:prod").state == PeerState.ACTIVE


def test_apply_revocation_notice_ignores_wrong_federation():
    issuer_key = generate_key()
    table = MembershipTable()
    table.admit(MemberRecord(node_id="dir:org-b:prod", manifest_url="https://x/m.json"))
    notice = sign_model(
        RevocationNotice(
            federation_id="other",
            revoked_node_id="dir:org-b:prod",
            reason="removed",
            issued_at=datetime.now(timezone.utc),
            issuer="dir:org-a:prod",
        ),
        issuer_key,
        "issuer-k1",
    )

    state = apply_revocation_notice(
        table,
        notice,
        federation_id="f",
        trusted_issuer_keys={"issuer-k1": public_jwk(issuer_key)},
    )

    assert state == PeerState.ACTIVE
    assert table.get("dir:org-b:prod").state == PeerState.ACTIVE


def test_apply_revocation_notice_ignores_unknown_peer():
    issuer_key = generate_key()
    table = MembershipTable()
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="dir:unknown:prod",
            reason="removed",
            issued_at=datetime.now(timezone.utc),
            issuer="dir:org-a:prod",
        ),
        issuer_key,
        "issuer-k1",
    )

    state = apply_revocation_notice(
        table,
        notice,
        federation_id="f",
        trusted_issuer_keys={"issuer-k1": public_jwk(issuer_key)},
    )

    assert state is None


def test_ssrf_guard_blocks_private_hosts():
    with pytest.raises(SSRFError):
        _assert_public_host("https://localhost/x")
    with pytest.raises(SSRFError):
        _assert_public_host("http://127.0.0.1:8080/m.json")
    # explicit opt-in bypasses the check (used for local integration tests)
    _assert_public_host("http://127.0.0.1/x", allow_private=True)
