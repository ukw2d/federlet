"""Integration tests: two federated stores, plus a third joining."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

import pytest

from federlet import (
    AdmissionPolicy,
    FederationClient,
    IntroduceRequest,
    Manifest,
    bootstrap_from_seeds,
)
from federlet import (
    FederationNode as FederationNodeFacade,
)
from federlet.crypto import b64u_encode
from federlet.lowlevel import build_signed_request
from federlet.signing import sign_dict
from harness import FederationNode

FED = "supplier-network-prod"

log = logging.getLogger("federlet.test")


def step(msg: str) -> None:
    log.info("\n>>> %s", msg)


def _client(node: FederationNode) -> FederationClient:
    return FederationClient(
        node_id=node.node_id,
        federation_id=FED,
        key=node.key,
        key_id=node.key_id,
        manifest_revision=node.manifest.revision,
        allow_private=True,
    )


def _intro_for(newcomer: FederationNode) -> IntroduceRequest:
    intro = IntroduceRequest(
        federation_id=newcomer.federation_id,
        manifest_url=newcomer.manifest_url,
        manifest=newcomer.manifest,
        nonce=b64u_encode(uuid.uuid4().bytes),
        timestamp=datetime.now(UTC),
    )
    data = sign_dict(
        intro.model_dump(mode="json", exclude_none=True), newcomer.key, newcomer.key_id
    )
    return IntroduceRequest.model_validate(data)


@pytest.fixture
def org_a():
    node = FederationNode("dir:org-a:prod", "org-a", FED).start()
    yield node
    node.stop()


@pytest.fixture
def org_b():
    node = FederationNode("dir:org-b:prod", "org-b", FED).start()
    yield node
    node.stop()


# --- Scenario 1: A and B already federate --------------------------------------


async def test_two_nodes_exchange_membership(org_a, org_b):
    step("SCENARIO 1: Org A and Org B already federate")

    step("A and B establish mutual trust (pre-seeded manifests)")
    org_a.seed(org_b)
    org_b.seed(org_a)

    step("A requests B's signed membership list")
    client = _client(org_a)
    members = await client.get_members(org_b.manifest)
    learned = {m.node_id for m in members.members}
    log.info("    A learned peers from B: %s", sorted(learned))
    assert "dir:org-a:prod" in learned
    await client.close()


async def test_client_probes_protocol_and_health(org_a, org_b):
    step("SCENARIO 1b: Org A probes Org B protocol and health")
    client = _client(org_a)
    try:
        protocol = await client.get_protocol(org_b.manifest)
        health = await client.get_health(org_b.manifest)
    finally:
        await client.close()

    assert protocol.node_id == "dir:org-b:prod"
    assert protocol.manifest_revision == org_b.manifest.revision
    assert protocol.protocol_versions == ["example-federation/1"]
    assert protocol.auth_methods == ["signed_http"]
    assert health.node_id == "dir:org-b:prod"
    assert health.status == "ok"


# --- Scenario 2: Org C joins via introduction + membership exchange ------------


async def test_third_store_joins_and_becomes_discoverable(org_a, org_b):
    step("SCENARIO 2: Org C wants to join a network where A and B already federate")
    org_a.seed(org_b)
    org_b.seed(org_a)

    org_c = FederationNode("dir:org-c:prod", "org-c", FED).start()
    try:
        c_client = _client(org_c)

        step("C bootstraps: fetch seed manifests from A and B directly (SSRF-checked)")
        a_manifest = await c_client.fetch_manifest(org_a.manifest_url)
        b_manifest = await c_client.fetch_manifest(org_b.manifest_url)
        log.info(
            "    C fetched + verified manifests for %s and %s",
            a_manifest.node_id,
            b_manifest.node_id,
        )
        assert isinstance(a_manifest, Manifest)
        org_c._admit(a_manifest)
        org_c._admit(b_manifest)

        step("C introduces itself to A and B (each decides independently)")
        resp_a = await c_client.introduce(a_manifest, _intro_for(org_c))
        resp_b = await c_client.introduce(b_manifest, _intro_for(org_c))
        log.info(
            "    A accepted C: %s | B accepted C: %s", resp_a.accepted, resp_b.accepted
        )
        assert resp_a.accepted and resp_a.accepted_node_id == "dir:org-c:prod"
        assert resp_b.accepted
        assert "dir:org-c:prod" in org_a.peers

        step("Membership exchange: C asks A who else it knows -> learns about B")
        members = await c_client.get_members(a_manifest)
        learned = {m.node_id for m in members.members}
        log.info("    C learned peers from A: %s", sorted(learned))
        assert "dir:org-b:prod" in learned

        step("A's local membership table now includes the newly admitted C")
        a_client = _client(org_a)
        assert {m.node_id for m in org_a.eligible_peer_manifests()} == {
            "dir:org-b:prod",
            "dir:org-c:prod",
        }
        await a_client.close()
        await c_client.close()
    finally:
        org_c.stop()


async def test_seed_bootstrap_helper_fetches_admits_and_introduces(org_a, org_b):
    step("SCENARIO 2b: Org C bootstraps through seed helper")
    org_a.seed(org_b)
    org_b.seed(org_a)
    org_c = FederationNode("dir:org-c:prod", "org-c", FED).start()
    try:
        c_client = _client(org_c)
        report = await bootstrap_from_seeds(
            c_client,
            seed_manifest_urls=[org_a.manifest_url, org_b.manifest_url],
            local_manifest_url=org_c.manifest_url,
            local_manifest=org_c.manifest,
            policy=AdmissionPolicy(
                federation_id=FED,
                protocol_versions={"example-federation/1"},
                require_expires_at=False,
                require_https=False,
                allow_private_hosts=True,
            ),
        )

        assert not report.failed
        assert not report.rejected
        accepted_seed_ids = {
            o.seed_manifest.node_id for o in report.accepted if o.seed_manifest
        }
        assert accepted_seed_ids == {
            org_a.node_id,
            org_b.node_id,
        }
        assert all(o.response and o.response.accepted for o in report.accepted)
        assert org_c.node_id in org_a.peers
        assert org_c.node_id in org_b.peers
        await c_client.close()
    finally:
        org_c.stop()


async def test_stateful_facade_drives_bootstrap_discover_refresh_and_verify(
    org_a,
    org_b,
):
    step("SCENARIO 2c: stateful facade wraps common host workflows")
    org_a.seed(org_b)
    org_b.seed(org_a)
    org_c = FederationNode("dir:org-c:prod", "org-c", FED).start()
    facade = FederationNodeFacade(
        node_id=org_c.node_id,
        federation_id=FED,
        key=org_c.key,
        key_id=org_c.key_id,
        manifest_revision=org_c.manifest.revision,
        admission_policy=AdmissionPolicy(
            federation_id=FED,
            protocol_versions={"example-federation/1"},
            require_expires_at=False,
            require_https=False,
            allow_private_hosts=True,
        ),
        allow_private=True,
    )
    try:
        bootstrap = await facade.bootstrap_from_seeds(
            seed_manifest_urls=[org_a.manifest_url],
            local_manifest_url=org_c.manifest_url,
            local_manifest=org_c.manifest,
        )
        accepted_seed_ids = [
            o.seed_manifest.node_id for o in bootstrap.accepted if o.seed_manifest
        ]
        assert accepted_seed_ids == [org_a.node_id]
        assert facade.select_peers() == [org_a.manifest]

        discovery = await facade.discover()
        assert [o.node_id for o in discovery.accepted] == [org_b.node_id]
        assert {m.node_id for m in facade.select_peers()} == {
            org_a.node_id,
            org_b.node_id,
        }

        refresh = await facade.refresh_all()
        assert {d.action for d in refresh.values()} == {"unchanged"}

        body = b'{"query_id":"q-1"}'
        envelope = build_signed_request(
            org_a.key,
            org_a.key_id,
            federation_id=FED,
            source_node_id=org_a.node_id,
            target_node_id=org_c.node_id,
            method="POST",
            path="/federation/v1/query",
            body=body,
            source_manifest_revision=org_a.manifest.revision,
        )
        verified = await facade.verify_known_inbound(
            signature_header=envelope.model_dump_json(exclude_none=True),
            source_node_id=org_a.node_id,
            method="POST",
            path="/federation/v1/query",
            body=body,
        )
        assert verified.source_node_id == org_a.node_id
    finally:
        await facade.close()
        org_c.stop()


# --- Scenario 3: authentication is enforced ------------------------------------


async def test_unsigned_request_is_rejected(org_a, org_b):
    step("SCENARIO 3a: an UNSIGNED membership request must be rejected")
    org_a.seed(org_b)
    import httpx

    async with httpx.AsyncClient() as c:
        r = await c.get(f"{org_b.endpoint}/members")
    log.info("    B responded %d %s", r.status_code, r.json())
    assert r.status_code == 401
    assert r.json()["error"] == "missing_signature"


async def test_wrong_federation_introduction_is_rejected(org_a):
    step("SCENARIO 3b: an introduction from a DIFFERENT federation must be rejected")
    import httpx

    outsider = FederationNode("dir:evil:prod", "evil", "other-federation")
    outsider.start()
    try:
        client = FederationClient(
            node_id=outsider.node_id,
            federation_id="other-federation",
            key=outsider.key,
            key_id=outsider.key_id,
            allow_private=True,
        )
        # A rejects the introduction (403) because the federation does not match.
        with pytest.raises(httpx.HTTPStatusError) as exc:
            await client.introduce(org_a.manifest, _intro_for(outsider))
        log.info(
            "    A rejected outsider: %d %s",
            exc.value.response.status_code,
            exc.value.response.json(),
        )
        assert exc.value.response.status_code == 403
        assert exc.value.response.json()["reason"] == "wrong_federation"
        await client.close()
    finally:
        outsider.stop()
