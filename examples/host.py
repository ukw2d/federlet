"""Framework-neutral federation host wiring example.

Run from the repository root:

    uv run python examples/host.py

This intentionally uses only Python's stdlib `http.server` for inbound routes.
The important boundary is not the framework; it is how host code extracts the
actual method/path/body/header, selects local trust material, calls federlet's
verification helpers, and signs protocol responses.
"""

from __future__ import annotations

import asyncio
import json
import threading
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from federlet import (
    IntroduceRequest,
    IntroduceResponse,
    MemberRef,
    MembersResponse,
)
from federlet.lowlevel import SignedRequest, generate_key, public_jwk, sign_model
from federlet.prelude import (
    SIGNATURE_HEADER,
    FederationClient,
    Manifest,
    Membership,
    PublicKey,
    UnauthorizedPeerRequest,
    check_manifest,
    sign_manifest,
    verify_peer_request,
)

FEDERATION_ID = "example-federation"
PROTOCOL_VERSION = "agent-directory-federation/1"


class MemoryNonceCache:
    """Small in-process NonceCache implementation for local examples."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    async def set(
        self,
        key: str,
        value: object,
        expire: float | None = None,
        exist: bool | None = None,
    ) -> bool:
        if exist is False and key in self._seen:
            return False
        self._seen.add(key)
        return True


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Any) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _make_manifest(
    *,
    key: Any,
    key_id: str,
    node_id: str,
    org_id: str,
    endpoint: str,
) -> Manifest:
    now = datetime.now(UTC)
    manifest = Manifest(
        node_id=node_id,
        org_id=org_id,
        federations=[FEDERATION_ID],
        endpoint=endpoint,
        protocol_versions=[PROTOCOL_VERSION],
        revision=1,
        public_keys=[PublicKey(key_id=key_id, public_jwk=public_jwk(key))],
        membership=Membership(
            introduce_url=f"{endpoint}/members/introduce",
            members_url=f"{endpoint}/members",
        ),
        issued_at=now,
        expires_at=now + timedelta(days=7),
    )
    return sign_manifest(manifest, key, key_id)


class ExampleNode:
    """Host-owned node state.

    Federlet does not own this state: real services would replace these dicts
    with their database, policy engine, KMS, audit sink, and framework request
    objects.
    """

    def __init__(self, *, node_id: str, org_id: str) -> None:
        self.node_id = node_id
        self.org_id = org_id
        self.key = generate_key()
        self.key_id = f"{node_id}-k1"
        self.manifest: Manifest | None = None
        self.trusted_peers: dict[str, Manifest] = {}
        self.nonces = MemoryNonceCache()

    def publish_at(self, endpoint: str) -> None:
        self.manifest = _make_manifest(
            key=self.key,
            key_id=self.key_id,
            node_id=self.node_id,
            org_id=self.org_id,
            endpoint=endpoint,
        )

    def trust(self, peer: Manifest) -> None:
        self.trusted_peers[peer.node_id] = peer

    def _signed_members_response(self) -> dict[str, Any]:
        assert self.manifest is not None
        refs = [
            MemberRef(
                node_id=peer.node_id,
                org_id=peer.org_id,
                manifest_url=f"{peer.endpoint.removesuffix('/federation/v1')}"
                "/.well-known/agent-directory.json",
                manifest_revision=peer.revision,
            )
            for peer in self.trusted_peers.values()
        ]
        response = sign_model(
            MembersResponse(source_node_id=self.node_id, members=refs),
            self.key,
            self.key_id,
        )
        return response.model_dump(mode="json", exclude_none=True)

    async def authenticate_known_peer(
        self, *, signature_header: str | None, method: str, path: str, body: bytes
    ) -> tuple[bool, str]:
        if not signature_header:
            return False, "missing_signature"
        try:
            envelope = SignedRequest.model_validate_json(signature_header)
        except ValueError:
            return False, "malformed_envelope"
        peer = self.trusted_peers.get(envelope.source_node_id)
        if peer is None:
            return False, "unknown_peer"
        try:
            await verify_peer_request(
                signature_header=signature_header,
                peer_manifest=peer,
                self_node_id=self.node_id,
                method=method,
                path=path,
                body=body,
                cache=self.nonces,
            )
        except UnauthorizedPeerRequest as exc:
            return False, exc.reason
        return True, "ok"

    async def handle_members(self, signature_header: str | None) -> tuple[int, dict]:
        ok, reason = await self.authenticate_known_peer(
            signature_header=signature_header,
            method="GET",
            path="/federation/v1/members",
            body=b"",
        )
        if not ok:
            return 401, {"error": reason}
        return 200, self._signed_members_response()

    async def handle_introduce(
        self, body: bytes, signature_header: str | None
    ) -> tuple[int, dict]:
        intro = IntroduceRequest.model_validate_json(body)
        ok, reason = check_manifest(intro.manifest)
        if not ok:
            return 400, {"accepted": False, "reason": f"manifest_{reason}"}
        try:
            await verify_peer_request(
                signature_header=signature_header,
                peer_manifest=intro.manifest,
                self_node_id=self.node_id,
                method="POST",
                path="/federation/v1/members/introduce",
                body=body,
                cache=self.nonces,
            )
        except UnauthorizedPeerRequest as exc:
            return 401, {"accepted": False, "reason": exc.reason}
        self.trust(intro.manifest)
        response = sign_model(
            IntroduceResponse(
                accepted=True,
                accepted_node_id=intro.manifest.node_id,
                accepted_manifest_revision=intro.manifest.revision,
                known_peer_count=len(self.trusted_peers),
            ),
            self.key,
            self.key_id,
        )
        return 200, response.model_dump(mode="json", exclude_none=True)


class HostServer(AbstractContextManager["HostServer"]):
    def __init__(self, node: ExampleNode) -> None:
        self.node = node
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> HostServer:
        node = self.node

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                assert node.manifest is not None
                if self.path == "/.well-known/agent-directory.json":
                    _json_response(
                        self,
                        200,
                        node.manifest.model_dump(mode="json", exclude_none=True),
                    )
                    return
                if self.path == "/federation/v1/members":
                    status, payload = asyncio.run(
                        node.handle_members(self.headers.get(SIGNATURE_HEADER))
                    )
                    _json_response(self, status, payload)
                    return
                _json_response(self, 404, {"error": "not_found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                if self.path == "/federation/v1/members/introduce":
                    status, payload = asyncio.run(
                        node.handle_introduce(body, self.headers.get(SIGNATURE_HEADER))
                    )
                    _json_response(self, status, payload)
                    return
                _json_response(self, 404, {"error": "not_found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        endpoint = f"http://127.0.0.1:{self.server.server_port}/federation/v1"
        node.publish_at(endpoint)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)


async def main() -> None:
    org_a = ExampleNode(node_id="dir:org-a:prod", org_id="org-a")
    org_b = ExampleNode(node_id="dir:org-b:prod", org_id="org-b")
    with HostServer(org_a), HostServer(org_b):
        assert org_a.manifest is not None
        assert org_b.manifest is not None
        org_a.trust(org_b.manifest)
        org_b.trust(org_a.manifest)

        async with FederationClient(
            node_id=org_a.node_id,
            federation_id=FEDERATION_ID,
            key=org_a.key,
            key_id=org_a.key_id,
            manifest_revision=org_a.manifest.revision,
        ) as client:
            members = await client.get_members(org_b.manifest)

        print(
            f"{org_a.node_id} authenticated to {org_b.node_id}; "
            f"{org_b.node_id} returned {len(members.members)} member ref(s)."
        )


if __name__ == "__main__":
    asyncio.run(main())
