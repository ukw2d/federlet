"""Unit tests for the pure protocol core (no sockets)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from cashews import Cache
from pydantic import ValidationError

from federlet import (
    JWK,
    SIGNATURE_HEADER,
    AdmissionEvidence,
    AdmissionPolicy,
    Disclosure,
    DisclosurePolicy,
    DiscoveryRefreshReport,
    DomainProofEvidence,
    FederationNode,
    GenericAdmissionEvidence,
    HealthResponse,
    IntroduceRequest,
    IntroduceResponse,
    KeyContinuityPolicy,
    Manifest,
    ManifestLimits,
    ManifestRefreshDecision,
    ManifestVerificationError,
    MemberRecord,
    MemberRef,
    Membership,
    MembershipStore,
    MembershipTable,
    MembersResponse,
    MissingRevocationsEndpointError,
    OperationItem,
    OperationRequest,
    OperationResponse,
    PayloadProvenance,
    PeerHealthProbeResult,
    PeerState,
    ProtocolResponse,
    PublicKey,
    RateLimiter,
    ResponseSignatureError,
    RevocationNotice,
    RevocationsResponse,
    TokenBucketRateLimiter,
    UnauthorizedPeerRequest,
    VerifiedPeer,
    admit_manifest,
    apply_revocation_notice,
    audit_record,
    b64u_decode,
    b64u_encode,
    bootstrap_from_seeds,
    build_operation_item,
    build_signed_manifest,
    build_signed_request,
    canonical_bytes,
    check_body_size,
    check_key_continuity,
    check_manifest,
    disclose_members,
    domain_evidence_verifier,
    generate_key,
    probe_peer_health,
    public_jwk,
    public_key_from_jwk,
    refresh_all,
    refresh_discovered_members,
    refresh_peer_manifest,
    sha256_hex,
    sign_introduce_response,
    sign_manifest,
    sign_members_response,
    sign_model,
    sign_operation_item,
    sign_operation_payload,
    sign_operation_response,
    sign_revocations_response,
    verify_manifest,
    verify_operation_item,
    verify_peer_request,
    verify_response_signature,
    verify_revocation_notice,
    verify_signed_request,
    well_known_url,
)
from federlet.client import FederationClient
from federlet.net import SSRFError, _assert_public_host


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
        "node_id": "node:org-a:prod",
        "org_id": "org-a",
        "federations": ["f"],
        "endpoint": "https://node.org-a.example/federation/v1",
        "revision": 12,
        "public_keys": [PublicKey(key_id=key_id, public_jwk=public_jwk(key))],
        "membership": Membership(
            introduce_url="https://x/i", members_url="https://x/m"
        ),
    } | extra
    m = Manifest(**data)
    return sign_manifest(m, key, key_id)


def _discovery_policy() -> AdmissionPolicy:
    return AdmissionPolicy(
        federation_id="f",
        protocol_versions={"example-federation/1"},
        require_expires_at=False,
    )


def _discoverable_manifest(key, key_id="k1", **extra) -> Manifest:
    return _manifest(
        key,
        key_id,
        protocol_versions=["example-federation/1"],
        **extra,
    )


def test_manifest_sign_verify_and_tamper():
    key = generate_key()
    m = _manifest(key)
    assert verify_manifest(m)
    assert not verify_manifest(m.model_copy(update={"revision": 999}))


def test_build_signed_manifest_builds_standard_verifiable_manifest():
    key = generate_key()
    issued = datetime(2026, 7, 13, 10, 0, tzinfo=UTC)
    manifest = build_signed_manifest(
        key,
        "org-a-k1",
        node_id="node:org-a:prod",
        org_id="org-a",
        endpoint="https://node.org-a.example/federation/v1/",
        federations=["example-federation-prod"],
        protocol_versions=["example-federation/1"],
        extensions={
            "example": {
                "profile_url": "https://node.org-a.example/federation/v1/profile"
            }
        },
        limits=ManifestLimits(max_operation_rps_per_peer=3),
        issued_at=issued,
        ttl=timedelta(days=2),
    )

    assert manifest.endpoint == "https://node.org-a.example/federation/v1"
    assert (
        manifest.membership.introduce_url
        == "https://node.org-a.example/federation/v1/members/introduce"
    )
    assert manifest.membership.members_url.endswith("/members")
    assert manifest.extensions == {
        "example": {"profile_url": "https://node.org-a.example/federation/v1/profile"}
    }
    assert manifest.expires_at == issued + timedelta(days=2)
    assert manifest.signature is not None
    assert verify_manifest(manifest)


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


def test_manifest_optional_disclosure_limits_and_extensions_round_trip():
    key = generate_key()
    m = _manifest(
        key,
        extensions={
            "example": {
                "operations_url": "https://x/operations",
                "schema_url": "https://x/schema.json",
            }
        },
        disclosure={"default": "federation", "supports_partner_scopes": True},
        limits={
            "max_operation_rps_per_peer": 3,
            "max_operation_timeout_ms": 500,
            "max_operation_items": 25,
        },
    )
    assert isinstance(m.disclosure, Disclosure)
    assert isinstance(m.limits, ManifestLimits)
    assert verify_manifest(m)

    wire = m.model_dump(mode="json")
    assert wire["extensions"] == {
        "example": {
            "operations_url": "https://x/operations",
            "schema_url": "https://x/schema.json",
        }
    }
    assert wire["disclosure"] == {
        "default": "federation",
        "supports_partner_scopes": True,
    }
    assert wire["limits"] == {
        "max_operation_rps_per_peer": 3,
        "max_operation_timeout_ms": 500,
        "max_operation_items": 25,
    }
    assert verify_manifest(Manifest.model_validate(wire))


def test_manifest_extension_fields_remain_optional():
    key = generate_key()
    m = _manifest(key)
    wire = m.model_dump(mode="json")
    assert wire["extensions"] == {}
    assert wire["disclosure"] is None
    assert wire["limits"] is None
    assert Manifest.model_validate(wire).extensions == {}
    assert Manifest.model_validate(wire).disclosure is None
    assert Manifest.model_validate(wire).limits is None


def test_manifest_missing_membership_key_raises_validation_error():
    key = generate_key()
    data = {
        "node_id": "node:org-a:prod",
        "org_id": "org-a",
        "endpoint": "https://node.org-a.example/federation/v1",
        "public_keys": [PublicKey(key_id="k1", public_jwk=public_jwk(key))],
        "membership": {"introduce_url": "https://x/i"},  # missing members_url
    }
    with pytest.raises(ValidationError):
        Manifest(**data)


def test_manifest_freshness_is_enforced():
    key = generate_key()
    now = datetime.now(UTC)

    fresh = _manifest(
        key,
        issued_at=_iso(now - timedelta(hours=1)),
        expires_at=_iso(now + timedelta(days=7)),
    )
    assert check_manifest(fresh) == (True, "ok")
    assert verify_manifest(fresh)

    expired = _manifest(
        key,
        issued_at=_iso(now - timedelta(days=8)),
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
    aware = datetime(
        2020, 1, 1, 12, 30, 15, 500_000, tzinfo=timezone(timedelta(hours=2))
    )
    m = _manifest(
        key, issued_at=aware, expires_at=datetime.now(UTC) + timedelta(days=1)
    )
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
    assert rt.accepted_until == datetime(2026, 7, 8, 8, 0, 0, tzinfo=UTC)
    assert rt.known_peer_count == 14

    # None stays None on the wire (no spurious empty string).
    assert (
        IntroduceResponse(accepted=True).model_dump(mode="json")["accepted_until"]
        is None
    )


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
    assert isinstance(
        Manifest.model_validate(wire).admission_evidence, DomainProofEvidence
    )


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
    now = datetime.now(UTC)
    manifest = _manifest(
        key,
        federations=["example-federation-prod"],
        protocol_versions=["example-federation/1"],
        endpoint="https://node.org-a.example/federation/v1",
        auth_methods=["signed_http"],
        admission_evidence={"type": "domain_proof", "domain": "org-a.example"},
        issued_at=_iso(now - timedelta(minutes=1)),
        expires_at=_iso(now + timedelta(days=7)),
    )
    decision = await admit_manifest(
        manifest,
        AdmissionPolicy(
            federation_id="example-federation-prod",
            protocol_versions={"example-federation/1"},
            evidence_verifier=domain_evidence_verifier,
        ),
    )
    assert decision.accepted
    assert decision.reason == "ok"


@pytest.mark.parametrize(
    "extra,reason",
    [
        ({"federations": ["other"]}, "wrong_federation"),
        ({"protocol_versions": ["unknown/1"]}, "unsupported_protocol"),
        ({"auth_methods": ["mtls"]}, "signed_http_required"),
        ({"endpoint": "http://node.org-a.example/federation/v1"}, "https_required"),
        ({"endpoint": "https://127.0.0.1/federation/v1"}, "private_endpoint_denied"),
    ],
)
async def test_admission_policy_rejects_bad_claims(extra, reason):
    key = generate_key()
    now = datetime.now(UTC)
    claims = {
        "federations": ["example-federation-prod"],
        "protocol_versions": ["example-federation/1"],
        "auth_methods": ["signed_http"],
        "issued_at": _iso(now - timedelta(minutes=1)),
        "expires_at": _iso(now + timedelta(days=7)),
    } | extra
    manifest = _manifest(key, **claims)
    decision = await admit_manifest(
        manifest,
        AdmissionPolicy(
            federation_id="example-federation-prod",
            protocol_versions={"example-federation/1"},
        ),
    )
    assert not decision.accepted
    assert decision.reason == reason


async def test_admission_policy_requires_expiry_by_default():
    key = generate_key()
    manifest = _manifest(
        key,
        federations=["example-federation-prod"],
        protocol_versions=["example-federation/1"],
    )
    policy = AdmissionPolicy(
        federation_id="example-federation-prod",
        protocol_versions={"example-federation/1"},
    )
    assert (await admit_manifest(manifest, policy)).reason == "missing_expires_at"


async def test_admission_accepts_custom_auth_method_via_host_hook():
    key = generate_key()
    manifest = _manifest(
        key,
        federations=["example-federation-prod"],
        protocol_versions=["example-federation/1"],
        auth_methods=["mtls"],
    )

    async def verify_mtls(_manifest):
        return True, "ok"

    policy = AdmissionPolicy(
        federation_id="example-federation-prod",
        protocol_versions={"example-federation/1"},
        require_expires_at=False,
        require_signed_http=False,  # host accepts mtls-only peers
        auth_method_verifiers={"mtls": verify_mtls},
    )
    decision = await admit_manifest(manifest, policy)
    assert decision.accepted
    assert decision.reason == "ok"


async def test_admission_rejects_advertised_method_when_host_hook_fails():
    key = generate_key()
    manifest = _manifest(
        key,
        federations=["example-federation-prod"],
        protocol_versions=["example-federation/1"],
        auth_methods=["signed_http", "mtls"],
    )

    async def verify_mtls(_manifest):
        return False, "cert_untrusted"

    policy = AdmissionPolicy(
        federation_id="example-federation-prod",
        protocol_versions={"example-federation/1"},
        require_expires_at=False,
        auth_method_verifiers={"mtls": verify_mtls},
    )
    decision = await admit_manifest(manifest, policy)
    assert not decision.accepted
    assert decision.reason == "cert_untrusted"


async def test_admission_ignores_verifier_for_unadvertised_method():
    key = generate_key()
    manifest = _manifest(
        key,
        federations=["example-federation-prod"],
        protocol_versions=["example-federation/1"],
        auth_methods=["signed_http"],  # does not advertise mtls
    )
    called = False

    async def verify_mtls(_manifest):
        nonlocal called
        called = True
        return False, "cert_untrusted"

    policy = AdmissionPolicy(
        federation_id="example-federation-prod",
        protocol_versions={"example-federation/1"},
        require_expires_at=False,
        auth_method_verifiers={"mtls": verify_mtls},
    )
    decision = await admit_manifest(manifest, policy)
    assert decision.accepted
    assert not called


async def test_domain_evidence_verifier_rejects_endpoint_outside_domain():
    key = generate_key()
    manifest = _manifest(
        key,
        endpoint="https://node.evil.example/federation/v1",
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
    assert not verify_response_signature(
        peer, signed.model_copy(update={"signature": None})
    )


def test_operation_request_round_trips_host_owned_payload_shape():
    req = OperationRequest(
        operation_id="op-123",
        operation="example.lookup",
        payload={
            "text": "host-specific intent",
            "filters": {"topic": ["alpha"], "action": ["lookup"]},
        },
        metadata={
            "requested_fields": ["id", "title"],
            "limit": 20,
            "timeout_ms": 2000,
            "routing_hint": "local-only",
        },
    )

    wire = req.model_dump(mode="json", exclude_none=True)
    assert wire["payload"]["filters"]["topic"] == ["alpha"]
    assert wire["metadata"]["routing_hint"] == "local-only"
    assert OperationRequest.model_validate(wire) == req


def test_operation_request_rejects_top_level_host_semantics():
    with pytest.raises(ValidationError):
        OperationRequest(
            operation_id="op-123",
            operation="example.lookup",
            requested_fields=["id"],
        )


def test_operation_item_sign_verify_and_tamper_detection():
    key = generate_key()
    owner = _manifest(key, node_id="node:org-c:prod", org_id="org-c")
    item = OperationItem(
        payload={
            "id": "item:org-c:example",
            "revision": 17,
            "title": "Example payload",
            "facets": {"topic": ["alpha"], "action": ["lookup"]},
        },
        provenance=PayloadProvenance(
            node_id=owner.node_id,
            content_hash=sha256_hex(b"canonical payload bytes"),
        ),
    )

    signed = sign_operation_item(item, key, "k1")

    assert signed.signature is not None
    assert verify_operation_item(owner, signed)
    assert not verify_operation_item(
        owner,
        signed.model_copy(
            update={
                "payload": {
                    **signed.payload,
                    "title": "Tampered",
                }
            }
        ),
    )
    assert not verify_operation_item(
        owner, signed.model_copy(update={"signature": None})
    )


def test_operation_item_rejects_top_level_host_semantics():
    with pytest.raises(ValidationError):
        OperationItem(
            item_id="item:org-c:example",
            payload={},
            provenance=PayloadProvenance(
                node_id="node:org-c:prod",
                content_hash=sha256_hex(b"payload"),
            ),
        )


def test_operation_item_rejects_wrong_owner_or_unknown_key():
    key = generate_key()
    owner = _manifest(key, node_id="node:org-c:prod", org_id="org-c")
    signed = sign_operation_payload(
        {"id": "item:org-c:example"},
        provenance=PayloadProvenance(
            node_id=owner.node_id,
            content_hash=sha256_hex(b"payload"),
        ),
        key=key,
        key_id="k1",
    )

    wrong_owner = owner.model_copy(update={"node_id": "node:other:prod"})
    unknown_key_owner = _manifest(
        generate_key(),
        key_id="other-k1",
        node_id=owner.node_id,
        org_id=owner.org_id,
    )

    assert not verify_operation_item(wrong_owner, signed)
    assert not verify_operation_item(unknown_key_owner, signed)


def test_operation_response_round_trips_signed_items_and_response_signature():
    key = generate_key()
    peer = _manifest(key, node_id="node:org-c:prod", org_id="org-c")
    signed_item = sign_operation_payload(
        {"id": "item:org-c:example"},
        provenance=PayloadProvenance(
            node_id=peer.node_id,
            content_hash=sha256_hex(b"payload"),
        ),
        key=key,
        key_id="k1",
    )
    resp = sign_operation_response(
        OperationResponse(
            operation_id="op-123",
            source_node_id=peer.node_id,
            payload={"status": "ok"},
            items=[signed_item],
            metadata={"truncated": False},
        ),
        key,
        "k1",
    )
    wire = resp.model_dump(mode="json", exclude_none=True)
    rt = OperationResponse.model_validate(wire)

    assert rt.metadata["truncated"] is False
    assert verify_response_signature(peer, rt)
    assert verify_operation_item(peer, rt.items[0])


def test_build_operation_item_accepts_mapping_payload():
    item = build_operation_item({"id": "item-1"})

    assert item.payload == {"id": "item-1"}


def test_standard_response_signing_helpers_are_verifiable():
    key = generate_key()
    peer = _manifest(key)

    assert verify_response_signature(
        peer,
        sign_introduce_response(
            IntroduceResponse(accepted=True, accepted_node_id=peer.node_id),
            key,
            "k1",
        ),
    )
    assert verify_response_signature(
        peer,
        sign_members_response(
            MembersResponse(source_node_id=peer.node_id),
            key,
            "k1",
        ),
    )
    assert verify_response_signature(
        peer,
        sign_revocations_response(
            RevocationsResponse(source_node_id=peer.node_id),
            key,
            "k1",
        ),
    )
    assert verify_response_signature(
        peer,
        sign_operation_response(
            OperationResponse(operation_id="op-123", source_node_id=peer.node_id),
            key,
            "k1",
        ),
    )


def test_revocation_notice_round_trips_and_verifies():
    key = generate_key()
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="node:org-b:prod",
            reason="removed",
            issued_at=datetime(2026, 7, 9, 10, 0, tzinfo=UTC),
            expires_at=datetime(2026, 7, 10, 10, 0, tzinfo=UTC),
            issuer="node:org-a:prod",
        ),
        key,
        "k1",
    )

    wire = notice.model_dump(mode="json")
    assert wire["issued_at"] == "2026-07-09T10:00:00Z"
    assert wire["expires_at"] == "2026-07-10T10:00:00Z"
    assert verify_revocation_notice(
        RevocationNotice.model_validate(wire), public_jwk(key)
    )
    assert RevocationsResponse(source_node_id="node:org-a:prod", notices=[notice])


def test_token_bucket_rate_limiter_allows_up_to_peer_manifest_rate():
    limiter: RateLimiter = TokenBucketRateLimiter(
        {
            "node:org-a:prod": ManifestLimits(max_operation_rps_per_peer=2),
        }
    )

    assert limiter.allow("node:org-a:prod", now=0.0)
    assert limiter.allow("node:org-a:prod", now=0.0)
    assert not limiter.allow("node:org-a:prod", now=0.0)


def test_token_bucket_rate_limiter_refills_over_time():
    limiter = TokenBucketRateLimiter(
        {
            "node:org-a:prod": ManifestLimits(max_operation_rps_per_peer=2),
        }
    )

    assert limiter.allow("node:org-a:prod", now=0.0)
    assert limiter.allow("node:org-a:prod", now=0.0)
    assert not limiter.allow("node:org-a:prod", now=0.25)
    assert limiter.allow("node:org-a:prod", now=0.5)
    assert not limiter.allow("node:org-a:prod", now=0.5)


def test_token_bucket_rate_limiter_treats_missing_limit_as_unbounded():
    limiter = TokenBucketRateLimiter(
        {
            "node:org-a:prod": ManifestLimits(),
        }
    )

    assert limiter.allow("unknown", now=0.0)
    assert limiter.allow("node:org-a:prod", now=0.0)
    assert limiter.allow("node:org-a:prod", now=0.0)


async def test_signed_request_roundtrip_and_replay(cache):
    key = generate_key()
    jwk = public_jwk(key)
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id="a",
        target_node_id="b",
        method="POST",
        path="/operations",
        body=b'{"x":1}',
    )
    first = await verify_signed_request(
        env,
        jwk,
        self_node_id="b",
        method="POST",
        path="/operations",
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
        path="/operations",
        body=b'{"x":1}',
        cache=cache,
    )
    assert replay == (False, "replay")


async def test_signed_request_body_size_limit_passes_under_limit(cache):
    key = generate_key()
    body = b'{"x":1}'
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id="a",
        target_node_id="b",
        method="POST",
        path="/operations",
        body=body,
    )

    assert check_body_size(body, len(body))
    assert await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="b",
        method="POST",
        path="/operations",
        body=body,
        max_body_bytes=len(body),
        cache=cache,
    ) == (True, "ok")


async def test_signed_request_body_size_limit_rejects_without_burning_nonce(cache):
    key = generate_key()
    body = b'{"payload":"too-large"}'
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id="a",
        target_node_id="b",
        method="POST",
        path="/operations",
        body=body,
    )

    assert not check_body_size(body, len(body) - 1)
    oversized = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="b",
        method="POST",
        path="/operations",
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
        path="/operations",
        body=body,
        cache=cache,
    )
    assert ok == (True, "ok")


async def test_replay_cache_key_is_scoped_to_request_context():
    key = generate_key()
    env = build_signed_request(
        key,
        "k1",
        federation_id="example-federation-prod",
        source_node_id="node:org-a:prod",
        target_node_id="node:org-b:prod",
        method="POST",
        path="/operations",
        body=b'{"x":1}',
    )
    cache = RecordingNonceCache()

    result = await verify_signed_request(
        env,
        public_jwk(key),
        self_node_id="node:org-b:prod",
        method="POST",
        path="/operations",
        body=b'{"x":1}',
        max_skew_seconds=120,
        cache=cache,
    )

    assert result == (True, "ok")
    assert cache.calls == [
        (
            f"federlet:nonce:example-federation-prod:node:org-a:prod:node:org-b:prod:{env.nonce}",
            1,
            120,
            False,
        )
    ]


async def test_bad_signature_does_not_burn_the_nonce(cache):
    # An unauthenticated request must not consume a nonce the real signer will
    # later use: the claim happens only after the signature verifies.
    key, attacker = generate_key(), generate_key()
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id="a",
        target_node_id="b",
        method="POST",
        path="/operations",
        body=b'{"x":1}',
    )
    forged = env.model_copy(update={"nonce": env.nonce})  # same nonce, wrong key below
    bad = await verify_signed_request(
        forged,
        public_jwk(attacker),
        self_node_id="b",
        method="POST",
        path="/operations",
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
        path="/operations",
        body=b'{"x":1}',
        cache=cache,
    )
    assert ok == (True, "ok")


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        (
            {
                "self_node_id": "b",
                "method": "POST",
                "path": "/operations",
                "body": b"{}",
            },
            "body_mismatch",
        ),
        (
            {
                "self_node_id": "wrong",
                "method": "POST",
                "path": "/operations",
                "body": b'{"x":1}',
            },
            "wrong_target",
        ),
        (
            {
                "self_node_id": "b",
                "method": "GET",
                "path": "/operations",
                "body": b'{"x":1}',
            },
            "method_mismatch",
        ),
        (
            {
                "self_node_id": "b",
                "method": "POST",
                "path": "/other",
                "body": b'{"x":1}',
            },
            "path_mismatch",
        ),
    ],
)
async def test_signed_request_rejections(kwargs, reason):
    key = generate_key()
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id="a",
        target_node_id="b",
        method="POST",
        path="/operations",
        body=b'{"x":1}',
    )
    ok, why = await verify_signed_request(env, public_jwk(key), **kwargs)
    assert not ok and why == reason


async def test_method_path_mismatch_does_not_burn_nonce(cache):
    key = generate_key()
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id="a",
        target_node_id="b",
        method="POST",
        path="/operations",
        body=b'{"x":1}',
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
        path="/operations",
        body=b'{"x":1}',
        cache=cache,
    )
    assert ok == (True, "ok")


async def test_verify_peer_request_returns_authenticated_identity(cache):
    key = generate_key()
    peer = _manifest(key)
    body = b'{"x":1}'
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id=peer.node_id,
        target_node_id="node:org-b:prod",
        method="POST",
        path="/operations",
        body=body,
        source_manifest_revision=peer.revision,
    )

    verified = await verify_peer_request(
        signature_header=env.model_dump_json(exclude_none=True),
        peer_manifest=peer,
        self_node_id="node:org-b:prod",
        method="POST",
        path="/operations",
        body=body,
        cache=cache,
    )

    assert verified == VerifiedPeer(
        source_node_id=peer.node_id,
        key_id="k1",
        source_manifest_revision=peer.revision,
        request_id=env.request_id,
    )


async def test_verify_peer_request_authenticates_introduction_from_embedded_manifest(
    cache,
):
    newcomer_key = generate_key()
    newcomer = _manifest(
        newcomer_key,
        node_id="node:org-c:prod",
        org_id="org-c",
        endpoint="https://node.org-c.example/federation/v1",
    )
    intro = IntroduceRequest(
        federation_id="f",
        manifest_url="https://node.org-c.example/manifest.json",
        manifest=newcomer,
        nonce="intro-nonce",
        timestamp=datetime.now(UTC),
    )
    body = intro.model_dump_json(exclude_none=True).encode()
    env = build_signed_request(
        newcomer_key,
        "k1",
        federation_id="f",
        source_node_id=newcomer.node_id,
        target_node_id="node:org-a:prod",
        method="POST",
        path="/federation/v1/members/introduce",
        body=body,
        source_manifest_revision=newcomer.revision,
    )

    verified = await verify_peer_request(
        signature_header=env.model_dump_json(exclude_none=True),
        peer_manifest=intro.manifest,
        self_node_id="node:org-a:prod",
        method="POST",
        path="/federation/v1/members/introduce",
        body=body,
        cache=cache,
    )

    assert verified.source_node_id == newcomer.node_id
    assert verified.key_id == "k1"
    assert verified.source_manifest_revision == newcomer.revision


@pytest.mark.parametrize(
    "signature_header,expected_reason",
    [
        (None, "missing_signature"),
        ("not-json", "malformed_envelope"),
    ],
)
async def test_verify_peer_request_rejects_malformed_headers(
    signature_header,
    expected_reason,
):
    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await verify_peer_request(
            signature_header=signature_header,
            peer_manifest=_manifest(generate_key()),
            self_node_id="b",
            method="POST",
            path="/operations",
            body=b"{}",
        )

    assert exc.value.reason == expected_reason


@pytest.mark.parametrize(
    "env_update,manifest_update,expected_reason",
    [
        ({"signature": None}, {}, "unsigned"),
        ({"target_node_id": "wrong"}, {}, "wrong_target"),
        ({}, {"node_id": "node:other:prod"}, "source_mismatch"),
    ],
)
async def test_verify_peer_request_rejects_invalid_envelopes(
    env_update,
    manifest_update,
    expected_reason,
):
    key = generate_key()
    peer = _manifest(key)
    body = b'{"x":1}'
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id=peer.node_id,
        target_node_id="b",
        method="POST",
        path="/operations",
        body=body,
        source_manifest_revision=peer.revision,
    ).model_copy(update=env_update)
    verifier_manifest = peer.model_copy(update=manifest_update)

    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await verify_peer_request(
            signature_header=env.model_dump_json(exclude_none=True),
            peer_manifest=verifier_manifest,
            self_node_id="b",
            method="POST",
            path="/operations",
            body=body,
        )

    assert exc.value.reason == expected_reason


async def test_verify_peer_request_rejects_unknown_key():
    key = generate_key()
    other_key = generate_key()
    peer = _manifest(other_key, key_id="other-k1")
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id=peer.node_id,
        target_node_id="b",
        method="POST",
        path="/operations",
        body=b"{}",
    )

    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await verify_peer_request(
            signature_header=env.model_dump_json(exclude_none=True),
            peer_manifest=peer,
            self_node_id="b",
            method="POST",
            path="/operations",
            body=b"{}",
        )

    assert exc.value.reason == "unknown_key"


async def test_verify_peer_request_rejects_replay(cache):
    key = generate_key()
    peer = _manifest(key)
    env = build_signed_request(
        key,
        "k1",
        federation_id="f",
        source_node_id=peer.node_id,
        target_node_id="b",
        method="POST",
        path="/operations",
        body=b"{}",
    )
    header = env.model_dump_json(exclude_none=True)
    kwargs = {
        "signature_header": header,
        "peer_manifest": peer,
        "self_node_id": "b",
        "method": "POST",
        "path": "/operations",
        "body": b"{}",
        "cache": cache,
    }

    await verify_peer_request(**kwargs)
    with pytest.raises(UnauthorizedPeerRequest) as exc:
        await verify_peer_request(**kwargs)

    assert exc.value.reason == "replay"


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
        return httpx.Response(
            200, json=signed.model_dump(mode="json", exclude_none=True)
        )

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
            revoked_node_id="node:org-b:prod",
            reason="removed",
            issued_at=datetime.now(UTC),
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
        return httpx.Response(
            200, json=signed.model_dump(mode="json", exclude_none=True)
        )

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


@pytest.mark.parametrize(
    "response_factory",
    [
        lambda peer, _: RevocationsResponse(source_node_id=peer.node_id),
        lambda peer, bad_key: sign_model(
            RevocationsResponse(source_node_id=peer.node_id),
            bad_key,
            "k1",
        ),
    ],
)
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
        return httpx.Response(
            200, json=response.model_dump(mode="json", exclude_none=True)
        )

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
        with pytest.raises(
            MissingRevocationsEndpointError, match="missing_revocations_url"
        ):
            await client.get_revocations(peer)
    finally:
        await client.close()


async def test_get_protocol_returns_parsed_response():
    import httpx

    peer_key = generate_key()
    peer = _manifest(peer_key)
    payload = {
        "node_id": peer.node_id,
        "manifest_revision": peer.revision,
        "protocol_versions": ["example-federation/1"],
        "auth_methods": ["signed_http"],
        "limits": {"max_operation_timeout_ms": 500},
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
    assert resp.protocol_versions == ["example-federation/1"]
    assert resp.auth_methods == ["signed_http"]
    assert resp.limits is not None
    assert resp.limits.max_operation_timeout_ms == 500
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
            return httpx.Response(
                200,
                json={
                    "node_id": peer.node_id,
                    "protocol_versions": ["example-federation/1"],
                },
            )
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
            return httpx.Response(
                200, json={"protocol_versions": ["example-federation/1"]}
            )
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
            return httpx.Response(
                200, json={"protocol_versions": ["example-federation/1"]}
            )
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
        return httpx.Response(
            200, json=signed.model_dump(mode="json", exclude_none=True)
        )

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
            manifest_url="https://caller.example/manifest.json",
            manifest=peer,
            nonce="n",
            timestamp=datetime.now(UTC),
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


@pytest.mark.parametrize(
    "manifest_update,reason",
    [
        ({"signature": None}, "unsigned"),
        ({"revision": 999}, "bad_signature"),
    ],
)
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
        return httpx.Response(
            200, json=current.model_dump(mode="json", exclude_none=True)
        )

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
        return httpx.Response(
            200, json=refreshed.model_dump(mode="json", exclude_none=True)
        )

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
    now = datetime.now(UTC)
    current = _manifest(peer_key, revision=12)
    expired = _manifest(
        peer_key,
        revision=13,
        issued_at=_iso(now - timedelta(days=8)),
        expires_at=_iso(now - timedelta(days=1)),
    )

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json=expired.model_dump(mode="json", exclude_none=True)
        )

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
        return httpx.Response(
            200, json=refreshed.model_dump(mode="json", exclude_none=True)
        )

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
        return httpx.Response(
            200, json=refreshed.model_dump(mode="json", exclude_none=True)
        )

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
        return httpx.Response(
            200, json=refreshed.model_dump(mode="json", exclude_none=True)
        )

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


async def test_refresh_all_returns_decisions_without_persistence():
    import httpx

    unchanged_key = generate_key()
    accepted_key = generate_key()
    quarantine_old_key, quarantine_new_key = generate_key(), generate_key()
    rejected_key = generate_key()
    unchanged = _manifest(
        unchanged_key, node_id="node:unchanged:prod", revision=12
    )
    accepted = _manifest(accepted_key, node_id="node:accepted:prod", revision=12)
    quarantine = _manifest(
        quarantine_old_key,
        key_id="quarantine-old-k1",
        node_id="node:quarantine:prod",
        revision=12,
    )
    rejected = _manifest(rejected_key, node_id="node:rejected:prod", revision=12)
    refreshed = {
        "/unchanged.json": unchanged,
        "/accepted.json": _manifest(
            accepted_key, node_id=accepted.node_id, revision=13
        ),
        "/quarantine.json": _manifest(
            quarantine_new_key,
            key_id="quarantine-new-k1",
            node_id=quarantine.node_id,
            revision=13,
        ),
        "/rejected.json": _manifest(
            rejected_key, node_id=rejected.node_id, revision=11
        ),
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=refreshed[request.url.path].model_dump(
                mode="json", exclude_none=True
            ),
        )

    table = MembershipTable()
    peers = {
        unchanged.node_id: unchanged,
        accepted.node_id: accepted,
        quarantine.node_id: quarantine,
        rejected.node_id: rejected,
    }
    targets = []
    for path, manifest in [
        ("/unchanged.json", unchanged),
        ("/accepted.json", accepted),
        ("/quarantine.json", quarantine),
        ("/rejected.json", rejected),
    ]:
        manifest_url = f"http://127.0.0.1{path}"
        table.admit(
            MemberRecord(
                node_id=manifest.node_id,
                manifest_url=manifest_url,
                manifest_revision=manifest.revision,
            )
        )
        targets.append((manifest, manifest_url))

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decisions = await refresh_all(client, targets)
    finally:
        await client.close()

    assert {node_id: d.action for node_id, d in decisions.items()} == {
        unchanged.node_id: "unchanged",
        accepted.node_id: "accept",
        quarantine.node_id: "quarantine",
        rejected.node_id: "reject",
    }
    assert decisions[accepted.node_id].new_revision == 13
    assert decisions[quarantine.node_id].reason == "stale_manifest"
    assert decisions[rejected.node_id].reason == "revision_rollback"
    assert {node_id: peer.revision for node_id, peer in peers.items()} == {
        unchanged.node_id: 12,
        accepted.node_id: 12,
        quarantine.node_id: 12,
        rejected.node_id: 12,
    }
    assert {
        rec.node_id: (rec.state, rec.manifest_revision)
        for rec in table.eligible_peers()
    } == {
        unchanged.node_id: (PeerState.ACTIVE, 12),
        accepted.node_id: (PeerState.ACTIVE, 12),
        quarantine.node_id: (PeerState.ACTIVE, 12),
        rejected.node_id: (PeerState.ACTIVE, 12),
    }


async def test_refresh_all_isolates_transport_failures_per_peer():
    import httpx

    ok_key, slow_key = generate_key(), generate_key()
    ok = _manifest(ok_key, node_id="node:ok:prod", revision=12)
    slow = _manifest(slow_key, node_id="node:slow:prod", revision=12)
    ok_refreshed = _manifest(ok_key, node_id=ok.node_id, revision=13)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ok.json":
            return httpx.Response(
                200, json=ok_refreshed.model_dump(mode="json", exclude_none=True)
            )
        raise httpx.ReadTimeout("slow peer", request=request)

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decisions = await refresh_all(
            client,
            [
                (ok, "http://127.0.0.1/ok.json"),
                (slow, "http://127.0.0.1/slow.json"),
            ],
        )
    finally:
        await client.close()

    assert decisions[ok.node_id].action == "accept"
    assert decisions[ok.node_id].new_revision == 13
    assert decisions[slow.node_id] == ManifestRefreshDecision(
        "quarantine",
        "timeout",
        old_revision=12,
    )


async def test_refresh_all_uses_key_continuity_policy():
    import httpx

    old_key, new_key = generate_key(), generate_key()
    current = _manifest(old_key, key_id="old-k1", revision=12)
    refreshed = _manifest(new_key, key_id="new-k1", revision=13)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json=refreshed.model_dump(mode="json", exclude_none=True)
        )

    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        decisions = await refresh_all(
            client,
            [(current, "http://127.0.0.1/manifest.json")],
            key_continuity_policy=KeyContinuityPolicy(allow_key_rotation=False),
        )
    finally:
        await client.close()

    decision = decisions[current.node_id]
    assert decision.action == "reject"
    assert decision.reason == "rotation_denied"
    assert decision.key_continuity is not None
    assert decision.key_continuity.action == "reject"


async def test_bootstrap_reports_source_node_and_manifest_url_for_each_bucket():
    import httpx

    accepted_key, rejected_key = generate_key(), generate_key()
    accepted = _discoverable_manifest(
        accepted_key,
        "accepted-k1",
        node_id="node:accepted:prod",
        org_id="accepted",
        manifest_url="http://127.0.0.1/accepted.json",
        membership=Membership(
            introduce_url="http://127.0.0.1/accepted/i",
            members_url="http://127.0.0.1/accepted/members",
        ),
    )
    rejected = _discoverable_manifest(
        rejected_key,
        "rejected-k1",
        node_id="node:rejected:prod",
        org_id="rejected",
        federations=["other"],
        manifest_url="http://127.0.0.1/rejected.json",
    )
    introduced = sign_introduce_response(
        IntroduceResponse(accepted=True, accepted_node_id="node:local:prod"),
        accepted_key,
        "accepted-k1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/accepted.json":
            return httpx.Response(
                200, json=accepted.model_dump(mode="json", exclude_none=True)
            )
        if request.url.path == "/accepted/i":
            return httpx.Response(
                200, json=introduced.model_dump(mode="json", exclude_none=True)
            )
        if request.url.path == "/rejected.json":
            return httpx.Response(
                200, json=rejected.model_dump(mode="json", exclude_none=True)
            )
        return httpx.Response(503, json={"error": "unavailable"})

    client = FederationClient(
        node_id="node:local:prod",
        federation_id="f",
        key=generate_key(),
        key_id="local-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        report = await bootstrap_from_seeds(
            client,
            seed_manifest_urls=[
                "http://127.0.0.1/accepted.json",
                "http://127.0.0.1/rejected.json",
                "http://127.0.0.1/failed.json",
            ],
            local_manifest_url="http://127.0.0.1/local.json",
            local_manifest=_discoverable_manifest(
                generate_key(),
                "local-manifest-k1",
                node_id="node:local:prod",
            ),
            policy=_discovery_policy(),
        )
    finally:
        await client.close()

    assert [
        (
            o.node_id,
            o.source_node_id,
            o.seed_manifest_url,
            o.manifest_url,
            o.reason,
        )
        for o in report.accepted
    ] == [
        (
            accepted.node_id,
            accepted.node_id,
            "http://127.0.0.1/accepted.json",
            "http://127.0.0.1/accepted.json",
            "ok",
        )
    ]
    assert [
        (
            o.node_id,
            o.source_node_id,
            o.seed_manifest_url,
            o.manifest_url,
            o.reason,
        )
        for o in report.rejected
    ] == [
        (
            rejected.node_id,
            rejected.node_id,
            "http://127.0.0.1/rejected.json",
            "http://127.0.0.1/rejected.json",
            "wrong_federation",
        )
    ]
    assert [
        (
            o.node_id,
            o.source_node_id,
            o.seed_manifest_url,
            o.manifest_url,
            o.reason,
        )
        for o in report.failed
    ] == [
        (
            None,
            None,
            "http://127.0.0.1/failed.json",
            "http://127.0.0.1/failed.json",
            "http_error",
        )
    ]


async def test_refresh_discovered_members_admits_new_peer_from_seed_hint():
    import httpx

    seed_key, new_key = generate_key(), generate_key()
    seed = _discoverable_manifest(
        seed_key,
        "seed-k1",
        node_id="node:seed:prod",
        org_id="seed",
        membership=Membership(
            introduce_url="http://127.0.0.1/seed/i",
            members_url="http://127.0.0.1/seed/members",
        ),
    )
    discovered = _discoverable_manifest(
        new_key,
        "new-k1",
        node_id="node:new:prod",
        org_id="new",
        endpoint="https://new.example/federation/v1",
    )
    members = sign_model(
        MembersResponse(
            source_node_id=seed.node_id,
            members=[
                MemberRef(
                    node_id=discovered.node_id,
                    org_id=discovered.org_id,
                    manifest_url="http://127.0.0.1/new.json",
                )
            ],
        ),
        seed_key,
        "seed-k1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/seed/members":
            return httpx.Response(
                200, json=members.model_dump(mode="json", exclude_none=True)
            )
        if request.url.path == "/new.json":
            return httpx.Response(
                200, json=discovered.model_dump(mode="json", exclude_none=True)
            )
        return httpx.Response(404, json={"error": "not_found"})

    table = MembershipTable()
    table.admit(
        MemberRecord(node_id=seed.node_id, manifest_url="http://127.0.0.1/seed.json")
    )
    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        report = await refresh_discovered_members(
            client,
            table,
            {seed.node_id: seed},
            _discovery_policy(),
        )
    finally:
        await client.close()

    assert isinstance(report, DiscoveryRefreshReport)
    assert [
        (o.node_id, o.manifest_url, o.source_node_id, o.reason)
        for o in report.accepted
    ] == [
        (
            discovered.node_id,
            "http://127.0.0.1/new.json",
            seed.node_id,
            "ok",
        )
    ]
    assert not report.rejected
    assert not report.skipped
    assert not report.failed
    rec = table.get(discovered.node_id)
    assert rec is not None
    assert rec.state == PeerState.ACTIVE
    assert rec.manifest_url == "http://127.0.0.1/new.json"
    assert rec.manifest_revision == discovered.revision


async def test_refresh_discovered_members_rejects_by_local_policy():
    import httpx

    seed_key, new_key = generate_key(), generate_key()
    seed = _discoverable_manifest(
        seed_key,
        "seed-k1",
        node_id="node:seed:prod",
        membership=Membership(
            introduce_url="http://127.0.0.1/seed/i",
            members_url="http://127.0.0.1/seed/members",
        ),
    )
    rejected_manifest = _discoverable_manifest(
        new_key,
        "new-k1",
        node_id="node:rejected:prod",
        federations=["other"],
    )
    members = sign_model(
        MembersResponse(
            source_node_id=seed.node_id,
            members=[
                MemberRef(
                    node_id=rejected_manifest.node_id,
                    manifest_url="http://127.0.0.1/rejected.json",
                )
            ],
        ),
        seed_key,
        "seed-k1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/seed/members":
            return httpx.Response(
                200, json=members.model_dump(mode="json", exclude_none=True)
            )
        return httpx.Response(
            200,
            json=rejected_manifest.model_dump(mode="json", exclude_none=True),
        )

    table = MembershipTable()
    table.admit(
        MemberRecord(node_id=seed.node_id, manifest_url="http://127.0.0.1/seed.json")
    )
    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        report = await refresh_discovered_members(
            client,
            table,
            {seed.node_id: seed},
            _discovery_policy(),
        )
    finally:
        await client.close()

    assert not report.accepted
    assert [
        (o.node_id, o.manifest_url, o.source_node_id, o.reason)
        for o in report.rejected
    ] == [
        (
            rejected_manifest.node_id,
            "http://127.0.0.1/rejected.json",
            seed.node_id,
            "wrong_federation",
        )
    ]
    assert table.get(rejected_manifest.node_id) is None


async def test_refresh_discovered_members_skips_self_existing_and_duplicate_hints():
    import httpx

    seed_key, new_key = generate_key(), generate_key()
    seed = _discoverable_manifest(
        seed_key,
        "seed-k1",
        node_id="node:seed:prod",
        membership=Membership(
            introduce_url="http://127.0.0.1/seed/i",
            members_url="http://127.0.0.1/seed/members",
        ),
    )
    duplicate_manifest = _discoverable_manifest(
        new_key,
        "dup-k1",
        node_id="node:dup:prod",
        federations=["other"],
    )
    members = sign_model(
        MembersResponse(
            source_node_id=seed.node_id,
            members=[
                MemberRef(node_id="caller", manifest_url="http://127.0.0.1/self.json"),
                MemberRef(
                    node_id=seed.node_id, manifest_url="http://127.0.0.1/seed.json"
                ),
                MemberRef(
                    node_id=duplicate_manifest.node_id,
                    manifest_url="http://127.0.0.1/dup.json",
                ),
                MemberRef(
                    node_id=duplicate_manifest.node_id,
                    manifest_url="http://127.0.0.1/dup.json",
                ),
            ],
        ),
        seed_key,
        "seed-k1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/seed/members":
            return httpx.Response(
                200, json=members.model_dump(mode="json", exclude_none=True)
            )
        if request.url.path == "/dup.json":
            return httpx.Response(
                200,
                json=duplicate_manifest.model_dump(mode="json", exclude_none=True),
            )
        raise AssertionError(f"unexpected fetch: {request.url}")

    table = MembershipTable()
    table.admit(
        MemberRecord(node_id=seed.node_id, manifest_url="http://127.0.0.1/seed.json")
    )
    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        report = await refresh_discovered_members(
            client,
            table,
            {seed.node_id: seed},
            _discovery_policy(),
        )
    finally:
        await client.close()

    assert [
        (o.node_id, o.manifest_url, o.source_node_id, o.reason)
        for o in report.skipped
    ] == [
        ("caller", "http://127.0.0.1/self.json", seed.node_id, "self"),
        (seed.node_id, "http://127.0.0.1/seed.json", seed.node_id, "existing_peer"),
        (
            duplicate_manifest.node_id,
            "http://127.0.0.1/dup.json",
            seed.node_id,
            "duplicate",
        ),
    ]
    assert [(o.node_id, o.reason) for o in report.rejected] == [
        (duplicate_manifest.node_id, "wrong_federation")
    ]


async def test_refresh_discovered_members_enforces_per_peer_cap():
    import httpx

    seed_key = generate_key()
    manifests = [
        _discoverable_manifest(generate_key(), f"k{i}", node_id=f"node:new-{i}:prod")
        for i in range(3)
    ]
    seed = _discoverable_manifest(
        seed_key,
        "seed-k1",
        node_id="node:seed:prod",
        membership=Membership(
            introduce_url="http://127.0.0.1/seed/i",
            members_url="http://127.0.0.1/seed/members",
        ),
    )
    members = sign_model(
        MembersResponse(
            source_node_id=seed.node_id,
            members=[
                MemberRef(
                    node_id=m.node_id, manifest_url=f"http://127.0.0.1/new-{i}.json"
                )
                for i, m in enumerate(manifests)
            ],
        ),
        seed_key,
        "seed-k1",
    )
    fetched: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/seed/members":
            return httpx.Response(
                200, json=members.model_dump(mode="json", exclude_none=True)
            )
        fetched.append(request.url.path)
        index = int(request.url.path.removeprefix("/new-").removesuffix(".json"))
        return httpx.Response(
            200, json=manifests[index].model_dump(mode="json", exclude_none=True)
        )

    table = MembershipTable()
    table.admit(
        MemberRecord(node_id=seed.node_id, manifest_url="http://127.0.0.1/seed.json")
    )
    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        report = await refresh_discovered_members(
            client,
            table,
            {seed.node_id: seed},
            _discovery_policy(),
            per_peer_cap=1,
        )
    finally:
        await client.close()

    assert [o.node_id for o in report.accepted] == [manifests[0].node_id]
    assert [(o.node_id, o.reason) for o in report.skipped] == [
        (manifests[1].node_id, "per_peer_cap"),
        (manifests[2].node_id, "per_peer_cap"),
    ]
    assert fetched == ["/new-0.json"]


async def test_refresh_discovered_members_reports_ssrf_rejected_manifest_url():
    import httpx

    seed_key = generate_key()
    seed = _discoverable_manifest(
        seed_key,
        "seed-k1",
        node_id="node:seed:prod",
        membership=Membership(
            introduce_url="https://seed.example/i",
            members_url="https://seed.example/members",
        ),
    )
    members = sign_model(
        MembersResponse(
            source_node_id=seed.node_id,
            members=[
                MemberRef(
                    node_id="node:private:prod",
                    manifest_url="http://127.0.0.1/private.json",
                )
            ],
        ),
        seed_key,
        "seed-k1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/members"
        return httpx.Response(
            200, json=members.model_dump(mode="json", exclude_none=True)
        )

    table = MembershipTable()
    table.admit(
        MemberRecord(
            node_id=seed.node_id, manifest_url="https://seed.example/manifest.json"
        )
    )
    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=False,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        report = await refresh_discovered_members(
            client,
            table,
            {seed.node_id: seed},
            _discovery_policy(),
        )
    finally:
        await client.close()

    assert not report.accepted
    assert [
        (o.node_id, o.manifest_url, o.source_node_id, o.reason)
        for o in report.failed
    ] == [
        (
            "node:private:prod",
            "http://127.0.0.1/private.json",
            seed.node_id,
            "ssrf_rejected",
        )
    ]


async def test_refresh_discovered_members_skips_node_id_mismatch():
    import httpx

    seed_key, other_key = generate_key(), generate_key()
    seed = _discoverable_manifest(
        seed_key,
        "seed-k1",
        node_id="node:seed:prod",
        membership=Membership(
            introduce_url="http://127.0.0.1/seed/i",
            members_url="http://127.0.0.1/seed/members",
        ),
    )
    other = _discoverable_manifest(other_key, "other-k1", node_id="node:other:prod")
    members = sign_model(
        MembersResponse(
            source_node_id=seed.node_id,
            members=[
                MemberRef(
                    node_id="node:expected:prod",
                    manifest_url="http://127.0.0.1/mismatch.json",
                )
            ],
        ),
        seed_key,
        "seed-k1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/seed/members":
            return httpx.Response(
                200, json=members.model_dump(mode="json", exclude_none=True)
            )
        return httpx.Response(
            200, json=other.model_dump(mode="json", exclude_none=True)
        )

    table = MembershipTable()
    table.admit(
        MemberRecord(node_id=seed.node_id, manifest_url="http://127.0.0.1/seed.json")
    )
    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        report = await refresh_discovered_members(
            client,
            table,
            {seed.node_id: seed},
            _discovery_policy(),
        )
    finally:
        await client.close()

    assert [(o.node_id, o.reason) for o in report.skipped] == [
        ("node:expected:prod", "node_id_mismatch")
    ]
    assert table.get("node:expected:prod") is None


async def test_refresh_discovered_members_isolates_fetch_failures():
    import httpx

    seed_key = generate_key()
    good = _discoverable_manifest(generate_key(), "good-k1", node_id="node:good:prod")
    seed = _discoverable_manifest(
        seed_key,
        "seed-k1",
        node_id="node:seed:prod",
        membership=Membership(
            introduce_url="http://127.0.0.1/seed/i",
            members_url="http://127.0.0.1/seed/members",
        ),
    )
    refs = [
        MemberRef(
            node_id="node:timeout:prod", manifest_url="http://127.0.0.1/timeout.json"
        ),
        MemberRef(node_id="node:http:prod", manifest_url="http://127.0.0.1/http.json"),
        MemberRef(
            node_id="node:bad-json:prod", manifest_url="http://127.0.0.1/bad-json.json"
        ),
        MemberRef(node_id=good.node_id, manifest_url="http://127.0.0.1/good.json"),
    ]
    members = sign_model(
        MembersResponse(source_node_id=seed.node_id, members=refs), seed_key, "seed-k1"
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/seed/members":
            return httpx.Response(
                200, json=members.model_dump(mode="json", exclude_none=True)
            )
        if request.url.path == "/timeout.json":
            raise httpx.ReadTimeout("slow peer")
        if request.url.path == "/http.json":
            return httpx.Response(503, json={"error": "unavailable"})
        if request.url.path == "/bad-json.json":
            return httpx.Response(200, content=b"not-json")
        if request.url.path == "/good.json":
            return httpx.Response(
                200, json=good.model_dump(mode="json", exclude_none=True)
            )
        return httpx.Response(404, json={"error": "not_found"})

    table = MembershipTable()
    table.admit(
        MemberRecord(node_id=seed.node_id, manifest_url="http://127.0.0.1/seed.json")
    )
    client = FederationClient(
        node_id="caller",
        federation_id="f",
        key=generate_key(),
        key_id="caller-k1",
        allow_private=True,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        report = await refresh_discovered_members(
            client,
            table,
            {seed.node_id: seed},
            _discovery_policy(),
        )
    finally:
        await client.close()

    assert [(o.node_id, o.reason) for o in report.failed] == [
        ("node:timeout:prod", "timeout"),
        ("node:http:prod", "http_error"),
        ("node:bad-json:prod", "malformed_manifest"),
    ]
    assert [o.node_id for o in report.accepted] == [good.node_id]
    assert table.get(good.node_id) is not None


def test_public_crypto_and_signing_helpers_are_exported():
    key = generate_key()
    jwk: JWK = public_jwk(key)
    assert AdmissionEvidence is not None
    assert public_key_from_jwk(jwk)
    assert b64u_decode(b64u_encode(b"abc")) == b"abc"
    assert canonical_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert sha256_hex(b"abc").startswith("sha256:")
    assert SIGNATURE_HEADER == "X-Federlet-Signature"


def test_tiered_public_api_namespaces_are_importable():
    from federlet import lowlevel, prelude

    assert prelude.FederationClient is FederationClient
    assert prelude.FederationNode is FederationNode
    assert prelude.Manifest is Manifest
    assert prelude.build_signed_manifest is build_signed_manifest
    assert prelude.verify_peer_request is verify_peer_request
    assert prelude.OperationItem is OperationItem
    assert prelude.OperationRequest is OperationRequest
    assert prelude.sign_members_response is sign_members_response
    assert prelude.sign_operation_item is sign_operation_item

    assert lowlevel.build_signed_request is build_signed_request
    assert lowlevel.verify_signed_request is verify_signed_request
    assert lowlevel.canonical_bytes is canonical_bytes
    assert lowlevel.sign_model is sign_model


def test_audit_record_includes_required_shape_and_timestamp():
    record = audit_record(
        event="admission_decision",
        request_id="req-1",
        source_node_id="node:org-a:prod",
        target_node_id="node:org-b:prod",
        manifest_revision=7,
        decision="accepted",
        reason="ok",
        extra={"transport": "http", "omitted": None},
    )

    assert record["event"] == "admission_decision"
    assert record["request_id"] == "req-1"
    assert record["source_node_id"] == "node:org-a:prod"
    assert record["target_node_id"] == "node:org-b:prod"
    assert record["manifest_revision"] == 7
    assert record["decision"] == "accepted"
    assert record["reason"] == "ok"
    assert record["transport"] == "http"
    assert "omitted" not in record
    assert record["timestamp"].endswith("Z")
    datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))


def test_audit_record_omits_none_optional_fields():
    record = audit_record(event="operation")

    assert record["event"] == "operation"
    assert "request_id" not in record
    assert "operation_id" not in record
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
    service: MembershipStore = table
    assert service is table


def test_disclose_members_excludes_ineligible_and_denied_peers():
    active = MemberRecord(
        node_id="node:org-a:prod",
        org_id="org-a",
        manifest_url="https://a.example/manifest.json",
        manifest_revision=2,
    )
    revoked = MemberRecord(
        node_id="node:org-b:prod",
        manifest_url="https://b.example/manifest.json",
        state=PeerState.REVOKED,
    )
    denied = MemberRecord(
        node_id="node:org-c:prod",
        manifest_url="https://c.example/manifest.json",
    )

    refs = disclose_members(
        [active, revoked, denied],
        requester_node_id="node:requester:prod",
        policy=DisclosurePolicy(default="federation", denied={"node:org-c:prod"}),
    )

    assert len(refs) == 1
    assert refs[0].node_id == "node:org-a:prod"
    assert refs[0].org_id == "org-a"
    assert refs[0].manifest_revision == 2
    assert refs[0].disclosure == "federation"


def test_disclose_members_applies_requester_specific_disclosure():
    rec = MemberRecord(
        node_id="node:org-a:prod",
        manifest_url="https://a.example/manifest.json",
    )

    refs = disclose_members(
        [rec],
        requester_node_id="node:requester:prod",
        policy=DisclosurePolicy(
            default="federation",
            requester_disclosure={"node:requester:prod": "partner"},
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
    table.admit(
        MemberRecord(node_id="node:org-b:prod", manifest_url="https://x/m.json")
    )
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="node:org-b:prod",
            reason="removed",
            issued_at=datetime.now(UTC),
            issuer="node:org-a:prod",
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
    assert table.get("node:org-b:prod").state == PeerState.REVOKED


def test_apply_revocation_notice_ignores_untrusted_issuer():
    issuer_key = generate_key()
    table = MembershipTable()
    table.admit(
        MemberRecord(node_id="node:org-b:prod", manifest_url="https://x/m.json")
    )
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="node:org-b:prod",
            reason="removed",
            issued_at=datetime.now(UTC),
            issuer="node:org-a:prod",
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
    assert table.get("node:org-b:prod").state == PeerState.ACTIVE


def test_apply_revocation_notice_ignores_wrong_federation():
    issuer_key = generate_key()
    table = MembershipTable()
    table.admit(
        MemberRecord(node_id="node:org-b:prod", manifest_url="https://x/m.json")
    )
    notice = sign_model(
        RevocationNotice(
            federation_id="other",
            revoked_node_id="node:org-b:prod",
            reason="removed",
            issued_at=datetime.now(UTC),
            issuer="node:org-a:prod",
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
    assert table.get("node:org-b:prod").state == PeerState.ACTIVE


def test_apply_revocation_notice_ignores_unknown_peer():
    issuer_key = generate_key()
    table = MembershipTable()
    notice = sign_model(
        RevocationNotice(
            federation_id="f",
            revoked_node_id="node:unknown:prod",
            reason="removed",
            issued_at=datetime.now(UTC),
            issuer="node:org-a:prod",
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


@pytest.mark.parametrize(
    ("base", "path", "expected"),
    [
        ("https://n.example", "manifest.json", "https://n.example/manifest.json"),
        ("https://n.example/", "manifest.json", "https://n.example/manifest.json"),
        ("https://n.example", "/manifest.json", "https://n.example/manifest.json"),
        ("https://n.example/", "/manifest.json", "https://n.example/manifest.json"),
        (
            "https://n.example/federation/v1/",
            "/members",
            "https://n.example/federation/v1/members",
        ),
        ("https://n.example", "", "https://n.example"),
        ("https://n.example/", "", "https://n.example"),
    ],
)
def test_well_known_url_normalizes_base_and_path(base, path, expected):
    assert well_known_url(base, path) == expected


def test_well_known_url_returns_absolute_path_unchanged():
    absolute = "https://other.example/already/absolute.json"
    assert well_known_url("https://n.example", absolute) == absolute


def test_well_known_url_rejects_non_absolute_base():
    with pytest.raises(ValueError):
        well_known_url("n.example/manifest", "manifest.json")
