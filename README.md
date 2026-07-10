# federlet

Federlet: a small async Python library for
hubless HTTPS federation between directory nodes.

federlet implements the protocol core from ADR-005:

- signed node manifests
- signed HTTP request envelopes
- freshness, skew, target, body-hash, and replay checks
- manifest admission policy
- membership state helpers
- an async client for manifest fetch, introduction, and member exchange

federlet does not run your service. Your application owns the HTTP server, key
storage, trust material, persistence, semantic query/fetch behavior,
observability, and deployment topology.

## Install

Use `uv` by default:

```bash
uv add federlet
```

For development in this repository:

```bash
uv sync
uv run pytest
```

If your service wants the optional recommended replay-cache backend:

```bash
uv add "federlet[cashews]"
```

With pip:

```bash
pip install federlet
pip install "federlet[cashews]"
```

## When to use federlet

Use federlet when independent directory nodes need to discover each other and make
signed, auditable requests without a central hub. Typical examples:

- two organizations already trust each other and want signed peer requests
- a new organization wants to join an existing federation through an introduction flow
- a service wants protocol semantics without adopting a bundled server framework

Do not use federlet as a complete federation server. It is the protocol library you
wire into your HTTP adapter, worker, or service runtime.

federlet deliberately does not implement semantic directory search, record fetch,
query fan-out, coverage calculation, principal mapping, namespace authorization,
or registry policy. Those belong to the host application.

## Core concepts

| Concern | federlet provides | Your application provides |
| --- | --- | --- |
| Manifests | Pydantic wire models, fetch-time verification, signing, freshness checks | key lifecycle, publication URL, revision policy |
| Signed requests | envelope creation and verification | request routing and response handling |
| Replay protection | `NonceCache` protocol and nonce-claim logic | the cache object passed at verification time |
| Rate limiting | `RateLimiter` protocol and in-memory `TokenBucketRateLimiter` | distributed per-peer limiter state |
| Admission | policy checks and verifier callback port | trust material and evidence validation rules |
| Federation calls | async `httpx` helpers for manifests, introductions, and members | peer selection, retries policy, logging, metrics |
| Server | no server | your HTTP stack, routing, middleware, and deployment runtime |

## Quick start

This example runs without a server. It creates two node manifests, admits one
peer under local policy, signs a request from node A to node B, and verifies it
with replay protection.

```python
import asyncio
from datetime import datetime, timedelta, timezone

from federlet import (
    AdmissionPolicy,
    Manifest,
    Membership,
    PublicKey,
    admit_manifest,
    build_signed_request,
    find_jwk,
    generate_key,
    public_jwk,
    sign_manifest,
    verify_signed_request,
)


class MemoryNonceCache:
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


def make_manifest(
    *,
    node_id: str,
    org_id: str,
    endpoint: str,
    key,
    key_id: str,
) -> Manifest:
    now = datetime.now(timezone.utc)
    manifest = Manifest(
        node_id=node_id,
        org_id=org_id,
        federations=["supplier-network-prod"],
        endpoint=endpoint,
        protocol_versions=["agent-directory-federation/1"],
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


async def main() -> None:
    key_a = generate_key()
    key_b = generate_key()
    manifest_a = make_manifest(
        node_id="dir:org-a:prod",
        org_id="org-a",
        endpoint="https://dir-a.example/federation/v1",
        key=key_a,
        key_id="org-a-k1",
    )
    manifest_b = make_manifest(
        node_id="dir:org-b:prod",
        org_id="org-b",
        endpoint="https://dir-b.example/federation/v1",
        key=key_b,
        key_id="org-b-k1",
    )

    decision = await admit_manifest(
        manifest_b,
        AdmissionPolicy(
            federation_id="supplier-network-prod",
            protocol_versions={"agent-directory-federation/1"},
        ),
    )
    assert decision.accepted, decision.reason

    body = b'{"operation":"example"}'
    envelope = build_signed_request(
        key_a,
        "org-a-k1",
        federation_id="supplier-network-prod",
        source_node_id=manifest_a.node_id,
        target_node_id=manifest_b.node_id,
        method="POST",
        path="/federation/v1/example",
        body=body,
        source_manifest_revision=manifest_a.revision,
    )
    assert envelope.signature is not None
    jwk = find_jwk(manifest_a.public_keys, envelope.signature.key_id)
    assert jwk is not None

    ok, reason = await verify_signed_request(
        envelope,
        jwk,
        self_node_id=manifest_b.node_id,
        method="POST",
        path="/federation/v1/example",
        body=body,
        cache=MemoryNonceCache(),
    )
    assert ok, reason
    print("verified")


asyncio.run(main())
```

Publish your signed manifest at a stable HTTPS URL controlled by your service.
Your HTTP adapter can then use the same verification function for inbound peer
requests.

## Host adapter sketch

Inbound federation endpoints should parse the detached signature envelope,
choose the sender's current public key from its trusted manifest, then verify
the request against the actual method, path, target node, and body bytes.

Replay protection is the one place federlet needs cache semantics. Pass any object
that implements `NonceCache.set(key, value, expire=..., exist=False)`. A
`cashews.Cache` works directly; in production, back it with Redis or Valkey.
Omitting `cache` disables replay protection and should be limited to tests or
special-purpose verification.

```python
from cashews import Cache

from federlet import SIGNATURE_HEADER, SignedRequest, find_jwk, verify_signed_request

nonce_cache = Cache()
nonce_cache.setup("redis://redis.internal:6379/0")


class UnauthorizedPeerRequest(ValueError):
    pass


async def verify_peer_request(
    *,
    signature_header: str | None,
    method: str,
    path: str,
    body: bytes,
    peer_manifest,
    self_node_id: str,
) -> None:
    if not signature_header:
        raise UnauthorizedPeerRequest("missing_signature")

    envelope = SignedRequest.model_validate_json(signature_header)
    if envelope.signature is None:
        raise UnauthorizedPeerRequest("unsigned")

    jwk = find_jwk(peer_manifest.public_keys, envelope.signature.key_id)
    if jwk is None:
        raise UnauthorizedPeerRequest("unknown_key")

    ok, reason = await verify_signed_request(
        envelope,
        jwk,
        self_node_id=self_node_id,
        method=method,
        path=path,
        body=body,
        cache=nonce_cache,
    )
    if not ok:
        raise UnauthorizedPeerRequest(reason)
```

Your HTTP adapter decides how to map `UnauthorizedPeerRequest` to a response
status and how to obtain the header value, for example from `SIGNATURE_HEADER`.

The nonce key is scoped by federation, source node, target node, and nonce. It
is claimed only after the signature, target, method, path, timestamp, and body
hash are valid. Failed unauthenticated requests do not consume nonces.

For per-peer request throttling, hosts can inject anything that implements the
`RateLimiter` protocol. `TokenBucketRateLimiter` is an in-memory reference
implementation that reads `Manifest.limits.max_query_rps_per_peer`; production
deployments should keep the bucket state in Redis, Valkey, or an equivalent
shared store.

For audit logging, `audit_record(...)` builds a flat ADR-shaped dict with an
ISO-Z timestamp. Feed that dict to your JSON logger, JSONL sink, or SIEM
adapter; federlet does not own logging transport.

## Admission

Admission is local policy. federlet validates the manifest signature, freshness,
federation id, protocol version, signed-HTTP support, HTTPS endpoint, and
optional endpoint domain limits. Stronger evidence, such as SPIFFE identities,
partner credentials, or charter keys, belongs in your callback.

```python
from federlet import AdmissionPolicy, admit_manifest, domain_evidence_verifier

policy = AdmissionPolicy(
    federation_id="supplier-network-prod",
    protocol_versions={"agent-directory-federation/1"},
    allowed_endpoint_domains={"example"},
    evidence_verifier=domain_evidence_verifier,
)

decision = await admit_manifest(peer_manifest, policy)
if not decision.accepted:
    raise ValueError(f"peer rejected: {decision.reason}")
```

## Protocol client

`FederationClient` verifies fetched manifests, signs outbound requests, and
verifies signed introduction and membership responses.

```python
from federlet import FederationClient

async with FederationClient(
    node_id="dir:org-a:prod",
    federation_id="supplier-network-prod",
    key=key,
    key_id=key_id,
    manifest_revision=signed_manifest.revision,
) as client:
    peer_manifest = await client.fetch_manifest(org_b_manifest_url)
    members = await client.get_members(peer_manifest)
```

Your application decides what to do with accepted peer manifests and member
references. federlet only signs and verifies the protocol exchange.

## Module Map

| Module | Purpose |
| --- | --- |
| `federlet.models` | Pydantic wire models for manifests, introductions, membership, signatures, and signed request envelopes. |
| `federlet.crypto` | Ed25519/JWK conversion, base64url helpers, and RFC 8785 canonical JSON bytes. |
| `federlet.signing` | Manifest signing/checking and signed request construction/verification. |
| `federlet.audit` | Pure audit record builder for host logging sinks. |
| `federlet.admission` | Local manifest admission checks and host-supplied evidence verifier protocol. |
| `federlet.membership` | In-memory membership state helpers; persistence remains host-owned. |
| `federlet.client` | Async `httpx` helpers for manifest fetch, introduction, and member exchange. |
| `federlet.protocols` | Structural protocols such as `NonceCache`, `RateLimiter`, and `MembershipStore` for Mongo/Postgres-backed hosts. |

## Usage scenarios

### Scenario: existing peers exchange membership

1. Org A and Org B exchange signed manifest URLs through an existing trust path.
2. Each service fetches and verifies the other's manifest.
3. Each service admits the peer with its local `AdmissionPolicy`.
4. Org A calls `get_members(org_b_manifest)`.
5. Org B verifies the signed request and signs the membership response.
6. Org A verifies the response signature and treats returned members as discovery hints.

This is the simplest steady-state deployment. No central directory is required.

### Scenario: a new peer joins

1. Org C starts with one or more seed manifest URLs for the federation.
2. Org C fetches and verifies those manifests with `fetch_manifest`.
3. Org C sends a signed `IntroduceRequest` to seed peers.
4. Each seed peer admits or rejects Org C independently.
5. Org C calls `get_members` to learn additional manifest URLs.
6. The host may include Org C in its own query or routing layer once local membership state marks it active.

The integration test in `tests/test_federation.py` exercises this flow with
three local nodes.

### Scenario: a peer is slow or unhealthy

1. The host probes or calls eligible peers on its own schedule.
2. The host records timeouts and transport failures.
3. `MembershipTable` can model cooldown for repeatedly failing peers.
4. A later host-observed success moves the peer back to active.

This keeps local peer selection useful during partial outages without making
federlet own a background scheduler.

## Production notes

- Store private keys in your platform key manager or secret store, not in code.
- Rotate keys by publishing overlapping `public_keys` in the manifest and
  advancing `revision`.
- Publish manifests over HTTPS and set `expires_at`; admission requires expiry
  by default.
- Keep `allow_private=False` outside local tests so manifest fetching and
  admission reject private, loopback, link-local, and reserved endpoints.
- Treat `domain_evidence_verifier` as a minimal sample for domain-shaped claims.
  Use your own verifier for real organizational trust.
- Add application metrics around admission decisions, verification failures, and
  peer cooldown state.

## Development

```bash
uv sync
uv run pytest
```

The tests include:

- manifest signing, freshness, and tamper checks
- signed request replay protection
- admission policy failures
- SSRF guard behavior
- introduction, membership exchange, and rejection scenarios

## API surface

Primary imports are re-exported from `federlet`:

```python
from federlet import (
    AdmissionDecision,
    AdmissionPolicy,
    EvidenceVerifier,
    FederationClient,
    IntroduceRequest,
    IntroduceResponse,
    JWK,
    Manifest,
    ManifestVerificationError,
    MemberRecord,
    MemberRef,
    Membership,
    MembersResponse,
    MembershipTable,
    NonceCache,
    PeerState,
    PublicKey,
    ResponseSignatureError,
    SIGNATURE_HEADER,
    SSRFError,
    Signature,
    SignedRequest,
    admit_manifest,
    b64u_decode,
    b64u_encode,
    build_signed_request,
    canonical_bytes,
    check_manifest,
    domain_evidence_verifier,
    find_jwk,
    generate_key,
    public_jwk,
    public_key_from_jwk,
    sha256_hex,
    sign_dict,
    sign_manifest,
    sign_model,
    verify_dict,
    verify_manifest,
    verify_model,
    verify_signed_request,
)
```

The lower-level signing helpers are public so downstream tests and host
adapters can construct signed fixtures without importing `federlet.signing`
directly. Production request verification should still go through
`verify_signed_request`, because it performs target, method, path, body-hash,
timestamp, signature, and nonce checks in one place.
