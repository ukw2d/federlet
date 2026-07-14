"""Tests for the generic operation fan-out helper (pimx-3yq.6).

Exercises the real sign -> send -> verify path through FederationClient backed by
an httpx.MockTransport, so no server is needed. The operations endpoint URL is
host-supplied per target (federlet resolves no endpoint paths).
"""

from __future__ import annotations

import httpx
import pytest

from federlet import (
    FederationClient,
    OperationRequest,
    OperationResponse,
    ResponseSignatureError,
    build_signed_manifest,
    fan_out_operation,
)
from federlet.lowlevel import generate_key, sign_model

FEDERATION_ID = "example-federation-prod"


def _peer(node_id: str, org_id: str):
    key = generate_key()
    key_id = f"{node_id}-k1"
    manifest = build_signed_manifest(
        key,
        key_id,
        node_id=node_id,
        org_id=org_id,
        endpoint=f"https://{org_id}.example/federation/v1",
        manifest_url=f"https://{org_id}.example/manifest.json",
        federations=[FEDERATION_ID],
        protocol_versions=["example-federation/1"],
    )
    ops_url = f"https://{org_id}.example/federation/v1/operations"
    return manifest, ops_url, key, key_id


def _signed_response(node_id: str, key, key_id: str) -> dict:
    resp = sign_model(
        OperationResponse(operation_id="op-1", source_node_id=node_id),
        key,
        key_id,
    )
    return resp.model_dump(mode="json", exclude_none=True)


def _client(handler) -> FederationClient:
    key = generate_key()
    return FederationClient(
        node_id="node:org-self:prod",
        federation_id=FEDERATION_ID,
        key=key,
        key_id="self-k1",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


def _request() -> OperationRequest:
    return OperationRequest(operation_id="op-1", operation="example.lookup")


async def test_fan_out_all_succeed():
    a, a_url, a_key, a_kid = _peer("node:org-a:prod", "org-a")
    b, b_url, b_key, b_kid = _peer("node:org-b:prod", "org-b")

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == a_url:
            return httpx.Response(200, json=_signed_response(a.node_id, a_key, a_kid))
        if str(request.url) == b_url:
            return httpx.Response(200, json=_signed_response(b.node_id, b_key, b_kid))
        return httpx.Response(404, json={"error": "not_found"})

    async with _client(handler) as client:
        report = await fan_out_operation(client, _request(), [(a, a_url), (b, b_url)])

    assert {o.node_id for o in report.succeeded} == {a.node_id, b.node_id}
    assert report.failed == []
    assert {
        (o.node_id, o.source_node_id, o.manifest_url, o.reason)
        for o in report.succeeded
    } == {
        (a.node_id, a.node_id, a.manifest_url, "ok"),
        (b.node_id, b.node_id, b.manifest_url, "ok"),
    }
    assert all(o.response is not None for o in report.succeeded)


async def test_fan_out_mixed_success_and_http_error():
    a, a_url, a_key, a_kid = _peer("node:org-a:prod", "org-a")
    b, b_url, _b_key, _b_kid = _peer("node:org-b:prod", "org-b")

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == a_url:
            return httpx.Response(200, json=_signed_response(a.node_id, a_key, a_kid))
        return httpx.Response(500, json={"error": "boom"})

    async with _client(handler) as client:
        report = await fan_out_operation(client, _request(), [(a, a_url), (b, b_url)])

    assert [o.node_id for o in report.succeeded] == [a.node_id]
    assert len(report.failed) == 1
    assert report.failed[0].node_id == b.node_id
    assert report.failed[0].source_node_id == b.node_id
    assert report.failed[0].manifest_url == b.manifest_url
    assert report.failed[0].reason == "http_error"
    assert report.failed[0].operations_url == b_url


async def test_fan_out_flags_bad_signature():
    a, a_url, _a_key, _a_kid = _peer("node:org-a:prod", "org-a")
    attacker_key = generate_key()

    def handler(request: httpx.Request) -> httpx.Response:
        # Response signed by a key the peer manifest does not advertise.
        return httpx.Response(
            200, json=_signed_response(a.node_id, attacker_key, "rogue-k1")
        )

    async with _client(handler) as client:
        report = await fan_out_operation(client, _request(), [(a, a_url)])

    assert report.succeeded == []
    assert report.failed[0].reason == "bad_signature"


async def test_fan_out_maps_timeout():
    a, a_url, _a_key, _a_kid = _peer("node:org-a:prod", "org-a")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow peer", request=request)

    async with _client(handler) as client:
        report = await fan_out_operation(client, _request(), [(a, a_url)])

    assert report.failed[0].reason == "timeout"


async def test_fan_out_empty_targets_is_empty_report():
    async def handler(request):  # pragma: no cover - never called
        raise AssertionError("no request should be sent")

    async with _client(handler) as client:
        report = await fan_out_operation(client, _request(), [])

    assert report.succeeded == []
    assert report.failed == []


async def test_send_operation_returns_verified_response():
    a, a_url, a_key, a_kid = _peer("node:org-a:prod", "org-a")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_signed_response(a.node_id, a_key, a_kid))

    async with _client(handler) as client:
        resp = await client.send_operation(a, _request(), operations_url=a_url)

    assert resp.operation_id == "op-1"
    assert resp.source_node_id == a.node_id


async def test_send_operation_raises_on_bad_signature():
    a, a_url, _a_key, _a_kid = _peer("node:org-a:prod", "org-a")
    attacker_key = generate_key()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json=_signed_response(a.node_id, attacker_key, "rogue-k1")
        )

    async with _client(handler) as client:
        with pytest.raises(ResponseSignatureError):
            await client.send_operation(a, _request(), operations_url=a_url)
