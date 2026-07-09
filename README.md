# pimx

Peer Introduction and Manifest Exchange: a small async Python library for
hubless HTTPS federation between directory nodes.

pimx implements the protocol core from ADR-005:

- signed node manifests
- signed HTTP request envelopes
- freshness, skew, target, body-hash, and replay checks
- manifest admission policy
- membership state helpers
- an async client for manifest fetch, introduction, and member exchange

pimx does not run your service. Your application owns the HTTP server, key
storage, trust material, persistence, semantic query/fetch behavior,
observability, and deployment topology.

## Install

Use `uv` by default:

```bash
uv add pimx
```

For development in this repository:

```bash
uv sync
uv run pytest
```

If your service wants the optional recommended replay-cache backend:

```bash
uv add "pimx[cashews]"
```

With pip:

```bash
pip install pimx
pip install "pimx[cashews]"
```

## When to use pimx

Use pimx when independent directory nodes need to discover each other and make
signed, auditable requests without a central hub. Typical examples:

- two organizations already trust each other and want signed peer requests
- a new organization wants to join an existing federation through an introduction flow
- a service wants protocol semantics without adopting a bundled server framework

Do not use pimx as a complete federation server. It is the protocol library you
wire into your HTTP adapter, worker, or service runtime.

pimx deliberately does not implement semantic directory search, record fetch,
query fan-out, coverage calculation, principal mapping, namespace authorization,
or registry policy. Those belong to the host application.

## Core concepts

| Concern | pimx provides | Your application provides |
| --- | --- | --- |
| Manifests | Pydantic wire models, fetch-time verification, signing, freshness checks | key lifecycle, publication URL, revision policy |
| Signed requests | envelope creation and verification | request routing and response handling |
| Replay protection | `NonceCache` protocol and nonce-claim logic | the cache object passed at verification time |
| Admission | policy checks and verifier callback port | trust material and evidence validation rules |
| Federation calls | async `httpx` helpers for manifests, introductions, and members | peer selection, retries policy, logging, metrics |
| Server | no server | your HTTP stack, routing, middleware, and deployment runtime |

## Quick start

### 1. Create and sign a manifest

```python
from datetime import datetime, timedelta, timezone

from pimx import Manifest, PublicKey, generate_key, public_jwk, sign_manifest

key = generate_key()
key_id = "ed25519-2026-01"
now = datetime.now(timezone.utc)

manifest = Manifest(
    node_id="dir:org-a:prod",
    org_id="org-a",
    federations=["supplier-network-prod"],
    endpoint="https://dir.org-a.example/federation/v1",
    protocol_versions=["agent-directory-federation/1"],
    revision=12,
    public_keys=[PublicKey(key_id=key_id, public_jwk=public_jwk(key))],
    membership={
        "introduce_url": "https://dir.org-a.example/federation/v1/introduce",
        "members_url": "https://dir.org-a.example/federation/v1/members",
    },
    admission_evidence={"type": "domain_proof", "domain": "org-a.example"},
    issued_at=now,
    expires_at=now + timedelta(days=7),
)

signed_manifest = sign_manifest(manifest, key, key_id)
```

Publish the signed manifest at a stable HTTPS URL controlled by your service.

### 2. Verify inbound signed requests

Inbound federation endpoints should parse the detached signature envelope,
choose the sender's current public key from its manifest, then verify the
request against the exact method, path, target node, and body bytes.

Replay protection is the one place pimx needs cache semantics. Pass any object
that implements `NonceCache.set(key, value, expire=..., exist=False)`. A
`cashews.Cache` works directly; in production, back it with Redis or Valkey.
Omitting `cache` disables replay protection and should be limited to tests or
special-purpose verification.

```python
from cashews import Cache

from pimx import SIGNATURE_HEADER, SignedRequest, find_jwk, verify_signed_request

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

### 3. Admit peer manifests

Admission is local policy. pimx validates the manifest signature, freshness,
federation id, protocol version, signed-HTTP support, HTTPS endpoint, and
optional endpoint domain limits. Stronger evidence, such as SPIFFE identities,
partner credentials, or charter keys, belongs in your callback.

```python
from pimx import AdmissionPolicy, admit_manifest, domain_evidence_verifier

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

### 4. Call peers for protocol exchange

`FederationClient` verifies fetched manifests, signs outbound requests, and
verifies signed introduction and membership responses.

```python
from pimx import FederationClient

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
references. pimx only signs and verifies the protocol exchange.

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
pimx own a background scheduler.

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

Primary imports are re-exported from `pimx`:

```python
from pimx import (
    AdmissionPolicy,
    FederationClient,
    IntroduceRequest,
    IntroduceResponse,
    JWK,
    Manifest,
    ManifestVerificationError,
    MembersResponse,
    MembershipTable,
    NonceCache,
    ResponseSignatureError,
    SIGNATURE_HEADER,
    SignedRequest,
    admit_manifest,
    b64u_decode,
    b64u_encode,
    build_signed_request,
    canonical_bytes,
    check_manifest,
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
adapters can construct signed fixtures without importing `pimx.signing`
directly. Production request verification should still go through
`verify_signed_request`, because it performs target, method, path, body-hash,
timestamp, signature, and nonce checks in one place.
