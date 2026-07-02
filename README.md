# pimx

Peer Introduction and Manifest Exchange: a small async Python library for
hubless HTTPS federation between directory nodes.

pimx implements the protocol core from ADR-005:

- signed node manifests
- signed HTTP request envelopes
- freshness, skew, target, body-hash, and replay checks
- manifest admission policy
- membership state helpers
- an async federation client for query, record fetch, introduction, and member exchange

pimx does not run your service. Your application owns the HTTP server, key
storage, trust material, persistence, observability, and deployment topology.

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

- two organizations already trust each other and want to federate directory queries
- a new organization wants to join an existing federation through an introduction flow
- a directory wants to return partial local results while reporting query coverage honestly
- a service wants protocol semantics without adopting a bundled server framework

Do not use pimx as a complete federation server. It is the protocol library you
wire into your ASGI, worker, or service runtime.

## Core concepts

| Concern | pimx provides | Your application provides |
| --- | --- | --- |
| Manifests | Pydantic wire models, signing, verification, freshness checks | key lifecycle, publication URL, revision policy |
| Signed requests | envelope creation and verification | request routing and response handling |
| Replay protection | `NonceCache` protocol and nonce-claim logic | the cache object passed at verification time |
| Admission | policy checks and verifier callback port | trust material and evidence validation rules |
| Federation calls | async `httpx` client helpers | peer selection, retries policy, logging, metrics |
| Server | no server | FastAPI, Starlette, aiohttp, or your existing HTTP stack |

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
from fastapi import HTTPException, Request

from pimx import SignedRequest, find_jwk, verify_signed_request

nonce_cache = Cache()
nonce_cache.setup("redis://redis.internal:6379/0")


async def verify_peer_request(
    request: Request,
    *,
    peer_manifest,
    self_node_id: str,
) -> None:
    raw_body = await request.body()
    envelope = SignedRequest.model_validate_json(request.headers["X-PIMX-Signature"])
    if envelope.signature is None:
        raise HTTPException(401, "unsigned")

    jwk = find_jwk(peer_manifest.public_keys, envelope.signature.key_id)
    if jwk is None:
        raise HTTPException(401, "unknown_key")

    ok, reason = await verify_signed_request(
        envelope,
        jwk,
        self_node_id=self_node_id,
        body=raw_body,
        cache=nonce_cache,
    )
    if not ok:
        raise HTTPException(401, reason)
```

The nonce key is scoped by federation, source node, target node, and nonce. It
is claimed only after the signature, target, timestamp, and body hash are valid.
Failed unauthenticated requests do not consume nonces.

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

### 4. Call peers

`FederationClient` signs outbound requests and verifies signed query responses.

```python
from pimx import FederationClient, Query

async with FederationClient(
    node_id="dir:org-a:prod",
    federation_id="supplier-network-prod",
    key=key,
    key_id=key_id,
    manifest_revision=signed_manifest.revision,
) as client:
    results, coverage = await client.federated_query(
        peers=[org_b_manifest, org_c_manifest],
        query=Query(
            query_id="q-2026-07-02-001",
            query={"text": "reconcile supplier invoices"},
            limit=10,
            timeout_ms=2000,
        ),
    )
```

`coverage` reports the local view: known peers, queried peers, responders,
timeouts, and skipped peers. It is not a global completeness claim.

## Usage scenarios

### Scenario: existing peers query each other

1. Org A and Org B exchange signed manifest URLs through an existing trust path.
2. Each service fetches and verifies the other's manifest.
3. Each service admits the peer with its local `AdmissionPolicy`.
4. Org A calls `federated_query([org_b_manifest], query)`.
5. Org B verifies the signed request, executes the local query, signs the response,
   and returns result cards.
6. Org A verifies the response signature and merges the results with coverage.

This is the simplest steady-state deployment. No central directory is required.

### Scenario: a new peer joins

1. Org C starts with one or more seed manifest URLs for the federation.
2. Org C fetches and verifies those manifests with `fetch_manifest`.
3. Org C sends a signed `IntroduceRequest` to seed peers.
4. Each seed peer admits or rejects Org C independently.
5. Org C calls `get_members` to learn additional manifest URLs.
6. Future queries include Org C once local membership state marks it active.

The integration test in `tests/test_federation.py` exercises this flow with
three local nodes.

### Scenario: a peer is slow or unhealthy

1. The client fans out a query to eligible local peers.
2. Timeouts and transport failures are recorded in `coverage`.
3. `MembershipTable` can move repeatedly failing peers into cooldown.
4. A later success moves the peer back to active.

This keeps the federation useful during partial outages while preserving an
honest report of which peers answered.

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
- Add application metrics around admission decisions, verification failures,
  query coverage, and peer cooldown state.

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
- federation query, introduction, membership exchange, and rejection scenarios

## API surface

Primary imports are re-exported from `pimx`:

```python
from pimx import (
    AdmissionPolicy,
    FederationClient,
    Manifest,
    MembershipTable,
    Query,
    SignedRequest,
    admit_manifest,
    build_signed_request,
    check_manifest,
    find_jwk,
    generate_key,
    public_jwk,
    sign_manifest,
    verify_manifest,
    verify_signed_request,
)
```
