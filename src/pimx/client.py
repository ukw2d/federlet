"""httpx client helpers for federation calls, with SSRF-safe manifest fetch."""

from __future__ import annotations

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
from .signing import build_signed_request, verify_dict

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
    jwk = next(
        (k.public_jwk for k in peer.public_keys
         if k.key_id == resp.signature.key_id),
        None,
    )
    if jwk is None:
        return False
    return verify_dict(resp.model_dump(exclude_none=True), jwk)


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
        client: httpx.Client | None = None,
    ) -> None:
        self.node_id = node_id
        self.federation_id = federation_id
        self.key = key
        self.key_id = key_id
        self.manifest_revision = manifest_revision
        self.allow_private = allow_private
        self._http = client or httpx.Client(timeout=10.0, follow_redirects=False)

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

    def fetch_manifest(self, manifest_url: str) -> Manifest:
        _assert_public_host(manifest_url, self.allow_private)
        r = self._http.get(manifest_url)
        r.raise_for_status()
        return Manifest.model_validate(r.json())

    def introduce(
        self, peer: Manifest, intro: IntroduceRequest
    ) -> IntroduceResponse:
        url = peer.membership["introduce_url"]
        body = intro.model_dump_json(exclude_none=True).encode()
        headers = self._signed_headers(
            peer.node_id, "POST", urlparse(url).path, body
        )
        r = self._http.post(url, content=body, headers=headers)
        r.raise_for_status()
        return IntroduceResponse.model_validate(r.json())

    def get_members(self, peer: Manifest, since: str | None = None) -> MembersResponse:
        url = peer.membership["members_url"]
        params = {"since": since} if since else None
        headers = self._signed_headers(
            peer.node_id, "GET", urlparse(url).path, b""
        )
        r = self._http.get(url, params=params, headers=headers)
        r.raise_for_status()
        return MembersResponse.model_validate(r.json())

    def query(self, peer: Manifest, query: Query) -> QueryResponse:
        url = peer.endpoint.rstrip("/") + "/query"
        body = query.model_dump_json(exclude_none=True).encode()
        headers = self._signed_headers(
            peer.node_id, "POST", urlparse(url).path, body
        )
        r = self._http.post(url, content=body, headers=headers)
        r.raise_for_status()
        return QueryResponse.model_validate(r.json())

    def federated_query(
        self, peers: list[Manifest], query: Query
    ) -> tuple[list[QueryResult], dict]:
        """Fan out a query to peers, verify signed responses, merge with coverage.

        Coverage is a truthful local-view report (ADR-005 §15), not a global
        completeness claim. Peers whose responses fail signature verification
        are counted as skipped.
        """
        results: list[QueryResult] = []
        responded, timed_out, skipped = [], [], []
        for peer in peers:
            try:
                resp = self.query(peer, query)
            except (httpx.TimeoutException, httpx.TransportError):
                timed_out.append(peer.node_id)
                continue
            except httpx.HTTPError:
                skipped.append({"node_id": peer.node_id, "reason": "http_error"})
                continue
            if not _verify_response(peer, resp):
                skipped.append({"node_id": peer.node_id, "reason": "bad_signature"})
                continue
            results.extend(resp.results)
            responded.append(peer.node_id)
        coverage = {
            "membership_view": "local",
            "known_peers": len(peers),
            "queried_peers": len(peers),
            "responded_peers": len(responded),
            "timed_out_peers": timed_out,
            "skipped_peers": skipped,
        }
        return results, coverage

    def fetch_record(
        self, peer: Manifest, record_id: str, fmt: str = "oasf"
    ) -> dict:
        url = f"{peer.endpoint.rstrip('/')}/records/{record_id}"
        headers = self._signed_headers(
            peer.node_id, "GET", urlparse(url).path, b""
        )
        r = self._http.get(url, params={"format": fmt}, headers=headers)
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        self._http.close()
