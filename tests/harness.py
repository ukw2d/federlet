"""In-process federation node for integration tests.

This is the *server side* deliberately kept OUT of the library: it wires federlet's
pure verifiers/signers into a stdlib http.server so tests can federate real
nodes over real sockets. A production host would do the same wiring in its HTTP
adapter and routing layer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
from collections.abc import Awaitable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TypeVar
from urllib.parse import urlparse

from cashews import Cache

from federlet import (
    DisclosurePolicy,
    IntroduceRequest,
    IntroduceResponse,
    Manifest,
    MemberRecord,
    Membership,
    MembershipTable,
    MembersResponse,
    PublicKey,
    SignedRequest,
    admit,
    disclose_members,
    eligible_peers,
    generate_key,
    public_jwk,
    sign_manifest,
    verify_manifest,
    verify_signed_request,
)
from federlet.signing import sign_model

T = TypeVar("T")


log = logging.getLogger("federlet.node")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FederationNode:
    def __init__(self, node_id: str, org_id: str, federation_id: str) -> None:
        self.node_id = node_id
        self.org_id = org_id
        self.federation_id = federation_id
        self.key = generate_key()
        self.key_id = f"{node_id}-k1"
        self.port = _free_port()
        base = f"http://127.0.0.1:{self.port}"
        self.manifest_url = f"{base}/manifest.json"
        self.endpoint = f"{base}/federation/v1"
        manifest = Manifest(
            node_id=node_id,
            org_id=org_id,
            federations=[federation_id],
            endpoint=self.endpoint,
            manifest_url=self.manifest_url,
            protocol_versions=["example-federation/1"],
            revision=1,
            public_keys=[
                PublicKey(key_id=self.key_id, public_jwk=public_jwk(self.key))
            ],
            membership=Membership(
                introduce_url=f"{self.endpoint}/members/introduce",
                members_url=f"{self.endpoint}/members",
            ),
        )
        self.manifest = sign_manifest(manifest, self.key, self.key_id)
        self.peers: dict[str, Manifest] = {}
        self.membership_table = MembershipTable()
        # Replay protection via a real cashews backend (mem:// here; a prod host
        # would point this at redis:// or valkey). federlet is async, so the sync
        # request handlers marshal awaits onto this node's dedicated loop.
        self.cache = Cache()
        self.cache.setup("mem://")
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._server: ThreadingHTTPServer | None = None

    def _log(self, msg: str) -> None:
        log.info("      [%s] %s", self.node_id, msg)

    def _run(self, coro: Awaitable[T]) -> T:
        """Run a federlet coroutine on this node's loop from a handler thread."""
        assert self._loop is not None
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    # --- peer bookkeeping ---------------------------------------------------

    def seed(self, other: FederationNode) -> None:
        """Pre-establish mutual knowledge (A and B already accept each other)."""
        self._log(f"seed: pre-trusting {other.node_id}")
        self._admit(other.manifest)

    def _admit(self, manifest: Manifest) -> None:
        self.peers[manifest.node_id] = manifest
        assert manifest.manifest_url is not None
        self.membership_table.upsert(
            admit(
                MemberRecord(
                    node_id=manifest.node_id,
                    manifest_url=manifest.manifest_url,
                    org_id=manifest.org_id,
                    manifest_revision=manifest.revision,
                )
            )
        )
        self._log(
            f"membership table now: {sorted(self.peers)} "
            f"(eligible={[r.node_id for r in eligible_peers(self.membership_table)]})"
        )

    def eligible_peer_manifests(self) -> list[Manifest]:
        return [
            self.peers[r.node_id]
            for r in eligible_peers(self.membership_table)
            if r.node_id in self.peers
        ]

    # --- inbound authentication --------------------------------------------

    def _authenticate(
        self,
        sig_header: str,
        *,
        method: str,
        path: str,
        body: bytes,
        source: Manifest | None = None,
    ) -> tuple[bool, str]:
        if not sig_header:
            return False, "missing_signature"
        env = SignedRequest.model_validate_json(sig_header)
        src = source or self.peers.get(env.source_node_id)
        if src is None:
            return False, "unknown_source"
        if env.signature is None:
            return False, "unsigned"
        jwk = next(
            (k.public_jwk for k in src.public_keys if k.key_id == env.signature.key_id),
            None,
        )
        if jwk is None:
            return False, "unknown_key"
        ok, reason = self._run(
            verify_signed_request(
                env,
                jwk,
                self_node_id=self.node_id,
                method=method,
                path=path,
                body=body,
                cache=self.cache,
            )
        )
        mark = "✓" if ok else "✗"
        self._log(
            f"{mark} auth {env.method} {env.path} from {env.source_node_id} "
            f"(key={env.signature.key_id}) → {reason}"
        )
        return ok, reason

    def _sign(self, model) -> dict:
        return sign_model(model, self.key, self.key_id).model_dump(
            mode="json", exclude_none=True
        )

    # --- handlers -----------------------------------------------------------

    def handle_introduce(self, body: bytes, sig_header: str) -> tuple[int, dict]:
        intro = IntroduceRequest.model_validate_json(body)
        m = intro.manifest
        self._log(f"← INTRODUCE from {m.node_id} (federation={intro.federation_id})")
        if not verify_manifest(intro.manifest):
            self._log("  ✗ manifest signature invalid → reject")
            return 400, IntroduceResponse(
                accepted=False, reason="bad_manifest"
            ).model_dump()
        self._log("  ✓ manifest signature valid")
        if (
            intro.federation_id != self.federation_id
            or self.federation_id not in m.federations
        ):
            self._log(
                f"  ✗ federation mismatch (mine={self.federation_id}, "
                f"theirs={m.federations}) → reject"
            )
            return 403, IntroduceResponse(
                accepted=False, reason="wrong_federation"
            ).model_dump()
        # newcomer is unknown; authenticate the request against its own manifest
        ok, reason = self._authenticate(
            sig_header,
            method="POST",
            path="/federation/v1/members/introduce",
            body=body,
            source=m,
        )
        if not ok:
            return 401, IntroduceResponse(accepted=False, reason=reason).model_dump()
        self._log(f"  → ADMIT {m.node_id}")
        self._admit(m)
        return 200, self._sign(
            IntroduceResponse(
                accepted=True,
                accepted_node_id=m.node_id,
                accepted_manifest_revision=m.revision,
            )
        )

    def handle_members(self, sig_header: str) -> tuple[int, dict]:
        self._log("← MEMBERS request")
        ok, reason = self._authenticate(
            sig_header, method="GET", path="/federation/v1/members", body=b""
        )
        if not ok:
            return 401, {"error": reason}
        self._log(f"  → disclosing {len(self.peers)} peer(s): {sorted(self.peers)}")
        members = disclose_members(
            eligible_peers(self.membership_table),
            requester_node_id="",
            policy=DisclosurePolicy(),
        )
        return 200, self._sign(
            MembersResponse(source_node_id=self.node_id, members=members)
        )

    # --- server lifecycle ---------------------------------------------------

    def start(self) -> FederationNode:
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._loop_thread.start()
        node = self
        SIG = "X-Federlet-Signature"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):  # silence
                pass

            def _send(self, status: int, payload: dict) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read(self) -> bytes:
                n = int(self.headers.get("Content-Length", 0))
                return self.rfile.read(n) if n else b""

            def do_GET(self):
                path = urlparse(self.path).path
                sig = self.headers.get(SIG, "")
                if path == "/manifest.json":
                    self._send(200, node.manifest.model_dump(exclude_none=True))
                elif path == "/federation/v1/protocol":
                    self._send(
                        200,
                        {
                            "node_id": node.node_id,
                            "manifest_revision": node.manifest.revision,
                            "protocol_versions": ["example-federation/1"],
                            "auth_methods": ["signed_http"],
                        },
                    )
                elif path == "/federation/v1/health":
                    self._send(200, {"node_id": node.node_id, "status": "ok"})
                elif path == "/federation/v1/members":
                    self._send(*node.handle_members(sig))
                else:
                    self._send(404, {"error": "not_found"})

            def do_POST(self):
                path = urlparse(self.path).path
                sig = self.headers.get(SIG, "")
                body = self._read()
                if path == "/federation/v1/members/introduce":
                    self._send(*node.handle_introduce(body, sig))
                else:
                    self._send(404, {"error": "not_found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self._log(f"node up, serving federation API at {self.endpoint}")
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._loop is not None:
            self._run(self.cache.close())  # cancel cashews' expiry sweeper cleanly
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._loop_thread is not None:
                self._loop_thread.join(timeout=2)
            self._loop.close()
            self._loop = None
