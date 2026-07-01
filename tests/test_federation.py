"""Integration tests: two federated stores, plus a third joining."""

from __future__ import annotations

import logging
import uuid

import pytest

from harness import FederationNode
from pimx import FederationClient, Manifest, Query, IntroduceRequest
from pimx.crypto import b64u_encode
from pimx.signing import _now, _iso, sign_dict

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
        timestamp=_iso(_now()),
    )
    data = sign_dict(intro.model_dump(exclude_none=True), newcomer.key, newcomer.key_id)
    return IntroduceRequest.model_validate(data)


@pytest.fixture
def org_a():
    node = FederationNode(
        "dir:org-a:prod", "org-a", FED,
        records=[{
            "record_id": "agent:org-a:po-agent", "record_type": "oasf-agent",
            "name": "Purchase Order Agent", "summary": "Creates purchase orders.",
            "skills": ["po.create"],
        }],
    ).start()
    yield node
    node.stop()


@pytest.fixture
def org_b():
    node = FederationNode(
        "dir:org-b:prod", "org-b", FED,
        records=[{
            "record_id": "agent:org-b:invoice-agent", "record_type": "oasf-agent",
            "name": "Invoice Reconciliation Agent",
            "summary": "Reconciles supplier invoices against purchase orders.",
            "skills": ["invoice.reconcile"],
        }],
    ).start()
    yield node
    node.stop()


# --- Scenario 1: A and B already federate --------------------------------------

def test_two_stores_query_and_fetch(org_a, org_b):
    step("SCENARIO 1: Org A and Org B already federate")

    step("A and B establish mutual trust (pre-seeded manifests)")
    org_a.seed(org_b)
    org_b.seed(org_a)

    step("A's requester runs a federated search: 'reconcile invoices'")
    client = _client(org_a)
    q = Query(query_id="q1", query={"text": "reconcile invoices"})
    results, coverage = client.federated_query(org_a.eligible_peer_manifests(), q)
    log.info("    A received %d card(s): %s", len(results), [r.record_id for r in results])
    log.info("    coverage: %s", coverage)

    assert [r.record_id for r in results] == ["agent:org-b:invoice-agent"]
    assert coverage["responded_peers"] == 1
    assert coverage["timed_out_peers"] == []
    assert coverage["membership_view"] == "local"

    step("A fetches the full record from its owner (Org B)")
    record = client.fetch_record(org_b.manifest, "agent:org-b:invoice-agent")
    log.info("    fetched full record: %s", record["record_id"])
    assert record["skills"] == ["invoice.reconcile"]
    client.close()


# --- Scenario 2: Org C joins via introduction + membership exchange ------------

def test_third_store_joins_and_becomes_queryable(org_a, org_b):
    step("SCENARIO 2: Org C wants to join a network where A and B already federate")
    org_a.seed(org_b)
    org_b.seed(org_a)

    org_c = FederationNode(
        "dir:org-c:prod", "org-c", FED,
        records=[{
            "record_id": "agent:org-c:supplier-agent", "record_type": "oasf-agent",
            "name": "Supplier Lookup Agent", "summary": "Looks up approved suppliers.",
            "skills": ["supplier.lookup"],
        }],
    ).start()
    try:
        c_client = _client(org_c)

        step("C bootstraps: fetch seed manifests from A and B directly (SSRF-checked)")
        a_manifest = c_client.fetch_manifest(org_a.manifest_url)
        b_manifest = c_client.fetch_manifest(org_b.manifest_url)
        log.info("    C fetched + verified manifests for %s and %s",
                 a_manifest.node_id, b_manifest.node_id)
        assert isinstance(a_manifest, Manifest)
        org_c._admit(a_manifest)
        org_c._admit(b_manifest)

        step("C introduces itself to A and B (each decides independently)")
        resp_a = c_client.introduce(a_manifest, _intro_for(org_c))
        resp_b = c_client.introduce(b_manifest, _intro_for(org_c))
        log.info("    A accepted C: %s | B accepted C: %s", resp_a.accepted, resp_b.accepted)
        assert resp_a.accepted and resp_a.accepted_node_id == "dir:org-c:prod"
        assert resp_b.accepted
        assert "dir:org-c:prod" in org_a.peers

        step("Membership exchange: C asks A who else it knows -> learns about B")
        members = c_client.get_members(a_manifest)
        learned = {m.node_id for m in members.members}
        log.info("    C learned peers from A: %s", sorted(learned))
        assert "dir:org-b:prod" in learned

        step("A now fans out a query including the newly-admitted C")
        a_client = _client(org_a)
        q = Query(query_id="q2", query={"filters": {"skills": ["supplier.lookup"]}})
        results, coverage = a_client.federated_query(org_a.eligible_peer_manifests(), q)
        owners = {r.record_id for r in results}
        log.info("    A received cards: %s", sorted(owners))
        log.info("    coverage: %s", coverage)
        assert "agent:org-c:supplier-agent" in owners
        assert coverage["known_peers"] == 2  # B and C
        assert coverage["responded_peers"] == 2
        a_client.close()
        c_client.close()
    finally:
        org_c.stop()


# --- Scenario 3: authentication is enforced ------------------------------------

def test_unsigned_request_is_rejected(org_a, org_b):
    step("SCENARIO 3a: an UNSIGNED query must be rejected")
    org_a.seed(org_b)
    import httpx

    body = Query(query_id="q3", query={"text": "anything"}).model_dump_json().encode()
    r = httpx.post(f"{org_b.endpoint}/query", content=body)
    log.info("    B responded %d %s", r.status_code, r.json())
    assert r.status_code == 401
    assert r.json()["error"] == "missing_signature"


def test_wrong_federation_introduction_is_rejected(org_a):
    step("SCENARIO 3b: an introduction from a DIFFERENT federation must be rejected")
    import httpx

    outsider = FederationNode("dir:evil:prod", "evil", "other-federation", records=[])
    outsider.start()
    try:
        client = FederationClient(
            node_id=outsider.node_id, federation_id="other-federation",
            key=outsider.key, key_id=outsider.key_id, allow_private=True,
        )
        # A rejects the introduction (403) because the federation does not match.
        with pytest.raises(httpx.HTTPStatusError) as exc:
            client.introduce(org_a.manifest, _intro_for(outsider))
        log.info("    A rejected outsider: %d %s",
                 exc.value.response.status_code, exc.value.response.json())
        assert exc.value.response.status_code == 403
        assert exc.value.response.json()["reason"] == "wrong_federation"
    finally:
        outsider.stop()
