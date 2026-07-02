"""httpx client helpers for federation calls, with SSRF-safe manifest fetch."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
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
from .signing import build_signed_request, find_jwk, verify_dict

SIGNATURE_HEADER = "X-PIMX-Signature"


class SSRFError(ValueError):
    """Raised when a manifest URL resolves to a disallowed address."""


def _assert_public_host(url: str, allow_private: bool = False) -> None:
    host = urlparse(url).hostname
    if not host:
        raise SSRFError(f"no host in url: {url}")
    if allow_private:
        return
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise SSRFError(f"{host} resolves to non-public address {ip}")


def _verify_response(peer: Manifest, resp: QueryResponse) -> bool:
    """Verify a signed response against the owning peer's advertised key."""
    if resp.signature is None:
        return False
    jwk = find_jwk(peer.public_keys, resp.signature.key_id)
    if jwk is None:
        return False
    return verify_dict(resp.model_dump(mode="json", exclude_none=True), jwk)


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
        r = await self._send(peer.node_id, "POST", peer.membership["introduce_url"], body=body)
        return IntroduceResponse.model_validate(r.json())

    async def get_members(self, peer: Manifest, since: str | None = None) -> MembersResponse:
        params = {"since": since} if since else None
        r = await self._send(peer.node_id, "GET", peer.membership["members_url"], params=params)
        return MembersResponse.model_validate(r.json())

    async def query(self, peer: Manifest, query: Query) -> QueryResponse:
        url = peer.endpoint.rstrip("/") + "/query"
        body = query.model_dump_json(exclude_none=True).encode()
        r = await self._send(peer.node_id, "POST", url, body=body)
        return QueryResponse.model_validate(r.json())

    async def federated_query(
        self, peers: list[Manifest], query: Query
    ) -> tuple[list[QueryResult], dict]:
        """Fan out a query to peers concurrently, verify signed responses, merge.

        Coverage is a truthful local-view report (ADR-005 §15), not a global
        completeness claim. Peers whose responses fail signature verification
        are counted as skipped.
        """
        async def one(peer: Manifest) -> tuple[str, str, list[QueryResult] | None]:
            try:
                resp = await self.query(peer, query)
            except (httpx.TimeoutException, httpx.TransportError):
                return "timed_out", peer.node_id, None
            except httpx.HTTPError:
                return "http_error", peer.node_id, None
            if not _verify_response(peer, resp):
                return "bad_signature", peer.node_id, None
            return "ok", peer.node_id, resp.results

        results: list[QueryResult] = []
        responded, timed_out, skipped = [], [], []
        for outcome, node_id, payload in await asyncio.gather(*(one(p) for p in peers)):
            if outcome == "ok":
                responded.append(node_id)
                results.extend(payload or [])
            elif outcome == "timed_out":
                timed_out.append(node_id)
            else:
                skipped.append({"node_id": node_id, "reason": outcome})
        coverage = {
            "membership_view": "local",
            "known_peers": len(peers),
            "queried_peers": len(peers),
            "responded_peers": len(responded),
            "timed_out_peers": timed_out,
            "skipped_peers": skipped,
        }
        return results, coverage

    async def fetch_record(
        self, peer: Manifest, record_id: str, fmt: str = "oasf"
    ) -> dict:
        url = f"{peer.endpoint.rstrip('/')}/records/{record_id}"
        r = await self._send(peer.node_id, "GET", url, params={"format": fmt})
        return r.json()

    async def close(self) -> None:
        await self._http.aclose()
