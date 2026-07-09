"""Integration tests: two federated stores, plus a third joining."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import pytest

from harness import FederationNode
from pimx import FederationClient, Manifest, IntroduceRequest
from pimx.crypto import b64u_encode
from pimx.signing import sign_dict

FED = "supplier-network-prod"

log = logging.getLogger("pimx.test")


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
        timestamp=datetime.now(timezone.utc),
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
        log.info("    C fetched + verified manifests for %s and %s",
                 a_manifest.node_id, b_manifest.node_id)
        assert isinstance(a_manifest, Manifest)
        org_c._admit(a_manifest)
        org_c._admit(b_manifest)

        step("C introduces itself to A and B (each decides independently)")
        resp_a = await c_client.introduce(a_manifest, _intro_for(org_c))
        resp_b = await c_client.introduce(b_manifest, _intro_for(org_c))
        log.info("    A accepted C: %s | B accepted C: %s", resp_a.accepted, resp_b.accepted)
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
            node_id=outsider.node_id, federation_id="other-federation",
            key=outsider.key, key_id=outsider.key_id, allow_private=True,
        )
        # A rejects the introduction (403) because the federation does not match.
        with pytest.raises(httpx.HTTPStatusError) as exc:
            await client.introduce(org_a.manifest, _intro_for(outsider))
        log.info("    A rejected outsider: %d %s",
                 exc.value.response.status_code, exc.value.response.json())
        assert exc.value.response.status_code == 403
        assert exc.value.response.json()["reason"] == "wrong_federation"
        await client.close()
    finally:
        outsider.stop()
