"""httpx client helpers for federation calls, with SSRF-safe manifest fetch."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import (
    IntroduceRequest,
    IntroduceResponse,
    Manifest,
    MembersResponse,
    Query,
    QueryResponse,
    QueryResult,
)
from .net import _assert_public_host
from .signing import build_signed_request, find_jwk, verify_model

SIGNATURE_HEADER = "X-PIMX-Signature"


class ResponseSignatureError(ValueError):
    """Raised when a peer returns an unsigned or unverifiable response."""


@dataclass(frozen=True)
class SkippedPeer:
    node_id: str
    reason: str


@dataclass(frozen=True)
class Coverage:
    """Truthful local-view report for a federated_query fan-out (ADR-005 §15)."""

    membership_view: str
    known_peers: int
    queried_peers: int
    responded_peers: int
    timed_out_peers: list[str]
    skipped_peers: list[SkippedPeer]


def _verify_response(peer: Manifest, resp: QueryResponse) -> bool:
    """Verify a signed response against the owning peer's advertised key."""
    if resp.signature is None:
        return False
    jwk = find_jwk(peer.public_keys, resp.signature.key_id)
    if jwk is None:
        return False
    return verify_model(resp, jwk)


class FederationClient:
    def __init__(
        self,
        *,
        node_id: str,
        federation_id: str,
        key: Ed25519PrivateKey,
        key_id: str,
        manifest_revision: int = 0,
        allow_private: bool = False,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.node_id = node_id
        self.federation_id = federation_id
        self.key = key
        self.key_id = key_id
        self.manifest_revision = manifest_revision
        self.allow_private = allow_private
        self._http = client or httpx.AsyncClient(timeout=10.0, follow_redirects=False)

    async def __aenter__(self) -> "FederationClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    def _signed_headers(
        self, target_node_id: str, method: str, path: str, body: bytes
    ) -> dict[str, str]:
        env = build_signed_request(
            self.key,
            self.key_id,
            federation_id=self.federation_id,
            source_node_id=self.node_id,
            target_node_id=target_node_id,
            method=method,
            path=path,
            body=body,
            source_manifest_revision=self.manifest_revision,
        )
        return {SIGNATURE_HEADER: env.model_dump_json(exclude_none=True)}

    async def _send(
        self,
        target_node_id: str,
        method: str,
        url: str,
        *,
        body: bytes = b"",
        params: dict | None = None,
    ) -> httpx.Response:
        """Sign, send, and raise-for-status a single federation call."""
        headers = self._signed_headers(target_node_id, method, urlparse(url).path, body)
        r = await self._http.request(
            method, url, content=body or None, params=params, headers=headers
        )
        r.raise_for_status()
        return r

    async def fetch_manifest(self, manifest_url: str) -> Manifest:
        # DNS resolution is blocking; keep the SSRF guard off the event loop.
        await asyncio.get_running_loop().run_in_executor(
            None, _assert_public_host, manifest_url, self.allow_private
        )
        r = await self._http.get(manifest_url)
        r.raise_for_status()
        return Manifest.model_validate(r.json())

    async def introduce(
        self, peer: Manifest, intro: IntroduceRequest
    ) -> IntroduceResponse:
        body = intro.model_dump_json(exclude_none=True).encode()
        r = await self._send(peer.node_id, "POST", peer.membership.introduce_url, body=body)
        return IntroduceResponse.model_validate(r.json())

    async def get_members(self, peer: Manifest, since: str | None = None) -> MembersResponse:
        params = {"since": since} if since else None
        r = await self._send(peer.node_id, "GET", peer.membership.members_url, params=params)
        return MembersResponse.model_validate(r.json())

    async def query(self, peer: Manifest, query: Query) -> QueryResponse:
        url = peer.endpoint.rstrip("/") + "/query"
        body = query.model_dump_json(exclude_none=True).encode()
        r = await self._send(peer.node_id, "POST", url, body=body)
        resp = QueryResponse.model_validate(r.json())
        if not _verify_response(peer, resp):
            raise ResponseSignatureError("bad_signature")
        return resp

    async def federated_query(
        self, peers: list[Manifest], query: Query
    ) -> tuple[list[QueryResult], Coverage]:
        """Fan out a query to peers concurrently, verify signed responses, merge.

        Coverage is a truthful local-view report (ADR-005 §15), not a global
        completeness claim. Peers whose responses fail signature verification
        are counted as skipped.
        """
        async def one(peer: Manifest) -> tuple[Manifest, QueryResponse | None, str | None]:
            try:
                return peer, await self.query(peer, query), None
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError):
                return peer, None, "timed_out"
            except ResponseSignatureError as exc:
                return peer, None, str(exc)

        responses = await asyncio.gather(*(one(p) for p in peers))

        results: list[QueryResult] = []
        for _, resp, _ in responses:
            if resp is not None:
                results.extend(resp.results)
        coverage = Coverage(
            membership_view="local",
            known_peers=len(peers),
            queried_peers=len(peers),
            responded_peers=sum(resp is not None for _, resp, _ in responses),
            timed_out_peers=[
                peer.node_id for peer, _, reason in responses if reason == "timed_out"
            ],
            skipped_peers=[
                SkippedPeer(node_id=peer.node_id, reason=reason)
                for peer, _, reason in responses
                if reason not in (None, "timed_out")
            ],
        )
        return results, coverage

    async def fetch_record(
        self, peer: Manifest, record_id: str, fmt: str = "oasf"
    ) -> dict:
        url = f"{peer.endpoint.rstrip('/')}/records/{record_id}"
        r = await self._send(peer.node_id, "GET", url, params={"format": fmt})
        return r.json()

    async def close(self) -> None:
        await self._http.aclose()
