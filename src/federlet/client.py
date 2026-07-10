"""httpx client helpers for federation calls, with SSRF-safe manifest fetch."""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import (
    CapabilitySummary,
    HealthResponse,
    IntroduceRequest,
    IntroduceResponse,
    Manifest,
    MembersResponse,
    ProtocolResponse,
    RevocationsResponse,
)
from .net import _assert_public_host
from .signing import build_signed_request, check_manifest, verify_response_signature

SIGNATURE_HEADER = "X-Federlet-Signature"


class ResponseSignatureError(ValueError):
    """Raised when a peer returns an unsigned or unverifiable response."""


class ManifestVerificationError(ValueError):
    """Raised when a fetched manifest is unsigned, stale, or unverifiable."""


class MissingRevocationsEndpointError(ValueError):
    """Raised when a peer manifest does not advertise a revocations endpoint."""


class MissingCapabilitySummaryEndpointError(ValueError):
    """Raised when a peer manifest does not advertise a capability summary endpoint."""


def _verify_response(
    peer: Manifest,
    resp: IntroduceResponse | MembersResponse | RevocationsResponse | CapabilitySummary,
) -> bool:
    return verify_response_signature(peer, resp)


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

    async def fetch_manifest(
        self, manifest_url: str, *, max_skew_seconds: int = 300
    ) -> Manifest:
        # DNS resolution is blocking; keep the SSRF guard off the event loop.
        await asyncio.get_running_loop().run_in_executor(
            None, _assert_public_host, manifest_url, self.allow_private
        )
        r = await self._http.get(manifest_url)
        r.raise_for_status()
        manifest = Manifest.model_validate(r.json())
        ok, reason = check_manifest(manifest, max_skew_seconds=max_skew_seconds)
        if not ok:
            raise ManifestVerificationError(reason)
        return manifest

    async def introduce(
        self, peer: Manifest, intro: IntroduceRequest
    ) -> IntroduceResponse:
        body = intro.model_dump_json(exclude_none=True).encode()
        r = await self._send(peer.node_id, "POST", peer.membership.introduce_url, body=body)
        resp = IntroduceResponse.model_validate(r.json())
        if not _verify_response(peer, resp):
            raise ResponseSignatureError("bad_signature")
        return resp

    async def get_members(self, peer: Manifest, since: str | None = None) -> MembersResponse:
        params = {"since": since} if since else None
        r = await self._send(peer.node_id, "GET", peer.membership.members_url, params=params)
        resp = MembersResponse.model_validate(r.json())
        if not _verify_response(peer, resp):
            raise ResponseSignatureError("bad_signature")
        return resp

    async def get_revocations(
        self, peer: Manifest, since: str | None = None
    ) -> RevocationsResponse:
        if peer.membership.revocations_url is None:
            raise MissingRevocationsEndpointError("missing_revocations_url")
        params = {"since": since} if since else None
        r = await self._send(peer.node_id, "GET", peer.membership.revocations_url, params=params)
        resp = RevocationsResponse.model_validate(r.json())
        if not _verify_response(peer, resp):
            raise ResponseSignatureError("bad_signature")
        return resp

    async def get_capability_summary(self, peer: Manifest) -> CapabilitySummary:
        if peer.capability_summary_url is None:
            raise MissingCapabilitySummaryEndpointError("missing_capability_summary_url")
        r = await self._send(peer.node_id, "GET", peer.capability_summary_url)
        resp = CapabilitySummary.model_validate(r.json())
        if not _verify_response(peer, resp):
            raise ResponseSignatureError("bad_signature")
        return resp

    async def get_protocol(self, peer: Manifest) -> ProtocolResponse:
        r = await self._send(peer.node_id, "GET", f"{peer.endpoint.rstrip('/')}/protocol")
        return ProtocolResponse.model_validate(r.json())

    async def get_health(self, peer: Manifest) -> HealthResponse:
        r = await self._send(peer.node_id, "GET", f"{peer.endpoint.rstrip('/')}/health")
        return HealthResponse.model_validate(r.json())

    async def close(self) -> None:
        await self._http.aclose()
