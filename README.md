# federlet

[![CI](https://github.com/ukw2d/federlet/actions/workflows/ci.yml/badge.svg)](https://github.com/ukw2d/federlet/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/federlet.svg)](https://pypi.org/project/federlet/)
[![Python versions](https://img.shields.io/pypi/pyversions/federlet.svg)](https://pypi.org/project/federlet/)
[![License](https://img.shields.io/pypi/l/federlet.svg)](https://github.com/ukw2d/federlet/blob/main/LICENSE)
[![Typed](https://img.shields.io/badge/typed-py.typed-blue.svg)](https://typing.python.org/en/latest/spec/distributing.html)
[![Ruff](https://img.shields.io/badge/lint-ruff-46a2f1.svg)](https://docs.astral.sh/ruff/)
[![mypy](https://img.shields.io/badge/types-mypy_checked-blue.svg)](https://mypy-lang.org/)

Federlet is an async Python library for decentralized, hubless federation
between peer directory services. It provides signed manifests, signed HTTP
requests, Ed25519 verification, replay protection, key-continuity checks, local
admission policy, SSRF-safe manifest fetching, health probing, revocations, and
peer discovery helpers.

Use federlet when independent services need zero-trust, service-to-service
federation without a central registry or control-plane hub. Your application
keeps control of HTTP routing, persistence, trust policy, key storage, semantic
search, observability, and deployment topology.

## At a glance

| Question | Answer |
| --- | --- |
| What is it? | A framework-neutral protocol library for peer directory federation. |
| Trust model | Signed manifests, Ed25519 signed requests, local admission policy, and key-continuity checks. |
| Runtime | Async Python, `httpx`, Pydantic v2, structural protocols for host-owned storage. |
| Deployment shape | No central hub, no bundled server, no required cache backend. |
| Host responsibilities | HTTP routing, persistence, private-key storage, trust material, semantic search, logging, metrics, and retries. |

## Features

federlet implements the protocol core from ADR-005:

- signed node manifests
- signed HTTP request envelopes for peer-to-peer calls
- Ed25519/JWK helpers and RFC 8785 canonical JSON signing
- freshness, clock-skew, target, method, path, body-hash, and replay checks
- local manifest admission policy and key-continuity checks
- SSRF protection for manifest URLs and admitted endpoints
- membership, revocation, manifest refresh, and discovery state helpers
- seed-bootstrap and capability-summary signing helpers
- optional stateful facade for common host workflows
- query envelope models and signed lightweight result-reference helpers
- protocol, health, revocation, capability-summary, and membership client calls
- structural protocols for host-owned nonce caches, rate limiters, and stores
- typed Pydantic models and `py.typed` packaging

federlet does not run your service. It is a framework-neutral protocol library
you wire into your HTTP adapter, worker, or service runtime.

## Install

Use `uv` by default:

```bash
uv add federlet
```

For development in this repository:

```bash
uv sync
uv run ruff check
uv run ruff format --check
uv run mypy src
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

## Choosing the API layer

Most applications should start with `federlet.prelude` or `FederationNode`.
Drop to `federlet.lowlevel` only when building tests, fixtures, or a custom
adapter that needs direct signing primitives.

| Layer | Use it for | Typical imports |
| --- | --- | --- |
| `FederationNode` | Stateful host integration around one local node: publish a manifest, verify inbound peer requests, bootstrap from seeds, discover peers, refresh known peers, and choose eligible peers. | `FederationNode`, `MembershipTable` |
| `federlet.prelude` | Functional integrations where the host owns state and calls individual helpers directly. This is the recommended import surface for most application code. | `build_signed_manifest`, `verify_peer_request`, `admit_manifest`, `FederationClient` |
| `federlet.lowlevel` | Tests, fixtures, custom protocol adapters, and advanced signing/verification flows. | `generate_key`, `sign_model`, `build_signed_request`, `verify_signed_request` |

Common integration paths:

- Publishing a node: build a signed manifest with `build_signed_manifest`, serve
  it from a stable HTTPS URL, and publish the URL through your existing trust or
  onboarding process.
- Authenticating inbound calls: look up the sender's trusted manifest, pass the
  raw signature header, method, path, and body to `verify_peer_request`, then map
  `UnauthorizedPeerRequest` to your HTTP error response.
- Joining a federation: call `bootstrap_from_seeds` or
  `FederationNode.bootstrap_from_seeds` with seed manifest URLs, then use
  discovery to turn signed membership hints into locally admitted peers.
- Serving protocol responses: sign standard response models with helpers such as
  `sign_members_response`, `sign_revocations_response`, and
  `sign_query_response`.
- Query/result-reference flows: parse `QueryRequest` in your application, perform
  local search and authorization in host code, then return signed lightweight
  `ResultRef` objects inside a signed `QueryResponse`.

## Quick start

This example runs without a server. It creates two node manifests, admits one
peer under local policy, signs a request from node A to node B, and verifies it
with replay protection.

```python
import asyncio

from federlet.prelude import (
    AdmissionPolicy,
    admit_manifest,
    build_signed_manifest,
    verify_peer_request,
)
from federlet.lowlevel import (
    build_signed_request,
    generate_key,
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

async def main() -> None:
    key_a = generate_key()
    key_b = generate_key()
    manifest_a = build_signed_manifest(
        key_a,
        "org-a-k1",
        node_id="dir:org-a:prod",
        org_id="org-a",
        endpoint="https://dir-a.example/federation/v1",
        federations=["supplier-network-prod"],
        protocol_versions=["example-federation/1"],
        manifest_url="https://dir-a.example/manifest.json",
    )
    manifest_b = build_signed_manifest(
        key_b,
        "org-b-k1",
        node_id="dir:org-b:prod",
        org_id="org-b",
        endpoint="https://dir-b.example/federation/v1",
        federations=["supplier-network-prod"],
        protocol_versions=["example-federation/1"],
        manifest_url="https://dir-b.example/manifest.json",
    )

    decision = await admit_manifest(
        manifest_b,
        AdmissionPolicy(
            federation_id="supplier-network-prod",
            protocol_versions={"example-federation/1"},
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
    verified = await verify_peer_request(
        signature_header=envelope.model_dump_json(exclude_none=True),
        peer_manifest=manifest_a,
        self_node_id=manifest_b.node_id,
        method="POST",
        path="/federation/v1/example",
        body=body,
        cache=MemoryNonceCache(),
    )
    assert verified.source_node_id == manifest_a.node_id
    print("verified")


asyncio.run(main())
```

Publish your signed manifest at a stable HTTPS URL controlled by your service.
Your HTTP adapter can then use the same verification function for inbound peer
requests.

## Host adapter sketch

For a runnable framework-neutral version, see
[`examples/host.py`](examples/host.py). It uses Python's stdlib HTTP server,
not a framework adapter, to show the protocol boundary.

Inbound federation endpoints should pass the detached signature envelope, the
actual method/path/body, and the sender's trusted manifest to
`verify_peer_request`. The helper parses the envelope, selects the advertised
key, verifies the signed request, and returns the authenticated peer identity.

Replay protection is the one place federlet needs cache semantics. Pass any object
that implements `NonceCache.set(key, value, expire=..., exist=False)`. A
`cashews.Cache` works directly; in production, back it with Redis or Valkey.
Omitting `cache` disables replay protection and should be limited to tests or
special-purpose verification.

```python
from cashews import Cache

from federlet import SIGNATURE_HEADER, UnauthorizedPeerRequest, verify_peer_request

nonce_cache = Cache()
nonce_cache.setup("redis://redis.internal:6379/0")


async def authenticate_peer_request(
    *,
    signature_header: str | None,
    method: str,
    path: str,
    body: bytes,
    peer_manifest,
    self_node_id: str,
) -> str:
    verified = await verify_peer_request(
        signature_header=signature_header,
        peer_manifest=peer_manifest,
        self_node_id=self_node_id,
        method=method,
        path=path,
        body=body,
        cache=nonce_cache,
    )
    return verified.source_node_id
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
    protocol_versions={"example-federation/1"},
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
| `federlet.prelude` | Small recommended import surface for common host integrations. |
| `federlet.lowlevel` | Advanced crypto/signing primitives for tests, fixtures, and custom adapters. |
| `federlet.bootstrap` | Thin seed-peer bootstrap loop over manifest fetch, admission, and introduction. |
| `federlet.capability` | Convenience builder for signed capability summaries. |
| `federlet.publication` | Convenience builder for signed node manifests. |
| `federlet.node` | Optional stateful facade over the functional protocol core. |
| `federlet.models` | Pydantic wire models for manifests, introductions, membership, signatures, and signed request envelopes. |
| `federlet.crypto` | Ed25519/JWK conversion, base64url helpers, and RFC 8785 canonical JSON bytes. |
| `federlet.signing` | Manifest signing/checking and signed request construction/verification. |
| `federlet.audit` | Pure audit record builder for host logging sinks. |
| `federlet.admission` | Local manifest admission checks and host-supplied evidence verifier protocol. |
| `federlet.membership` | In-memory membership state helpers; persistence remains host-owned. |
| `federlet.refresh` | One-shot manifest refresh and key-continuity decision helper. |
| `federlet.discovery` | Bounded peer discovery from signed membership hints. |
| `federlet.health` | Protocol and health probe classification helpers. |
| `federlet.query` | Query request/response wire models and signed result-reference helpers. |
| `federlet.net` | SSRF guard for manifest and endpoint URLs. |
| `federlet.client` | Async `httpx` helpers for manifest fetch, introduction, members, revocations, capability summaries, protocol, and health calls. |
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
2. Org C calls `bootstrap_from_seeds`, which fetches/verifies each seed
   manifest, applies local admission policy, and sends a signed introduction.
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

### Scenario: a peer returns query result references

1. The host receives a signed `POST /query` and authenticates it with
   `verify_peer_request`.
2. The host parses `QueryRequest`; local search, authorization, ranking, and
   coverage calculation stay in the host.
3. The host returns a `QueryResponse` containing lightweight `ResultRef`
   objects signed with `sign_result`.
4. Downstream hosts can merge references from many peers and still verify each
   reference's provenance with `verify_result`.

## Production notes

- Store private keys in your platform key manager or secret store, not in code.
- Rotate keys by publishing overlapping `public_keys` in the manifest and
  advancing `revision`.
- Publish manifests over HTTPS and set `expires_at`; admission requires expiry
  by default.
- Keep `allow_private=False` outside local tests so manifest fetching and
  admission reject private, loopback, link-local, and reserved endpoints.
- Treat `domain_evidence_verifier` as a minimal sample for DNS-domain-shaped
  admission claims. Use your own verifier for real organizational trust.
- Add application metrics around admission decisions, verification failures, and
  peer cooldown state.

## Development

```bash
uv sync
uv run ruff check
uv run ruff format --check
uv run mypy src
uv run pytest
```

The tests include:

- manifest signing, freshness, and tamper checks
- signed request replay protection
- admission policy failures
- SSRF guard behavior
- introduction, membership exchange, and rejection scenarios
- revocation, capability-summary, health, refresh, and discovery flows

## Versioning and releases

Release history is maintained in [`CHANGELOG.md`](CHANGELOG.md) using Keep a
Changelog-style sections.

federlet uses SemVer-style `MAJOR.MINOR.PATCH` versions and `vX.Y.Z` Git tags.
For every release, update `pyproject.toml`, move completed entries from
`Unreleased` into the release section, commit the change, and tag that exact
commit with the matching version, for example `v0.1.0`.

Until `1.0.0`, the public API should be treated as alpha-stage: patch releases
are reserved for backwards-compatible fixes and documentation updates, while
minor releases may include deliberate API changes when they are called out in the
changelog. After `1.0.0`, breaking public API changes require a major version
bump.

## API surface

For application integrations, prefer the high-level prelude:

```python
from federlet.prelude import (
    AdmissionPolicy,
    FederationClient,
    FederationNode,
    Manifest,
    Membership,
    MembershipTable,
    PublicKey,
    QueryRequest,
    QueryResponse,
    ResultRef,
    SIGNATURE_HEADER,
    SeedBootstrapReport,
    UnauthorizedPeerRequest,
    admit_manifest,
    bootstrap_from_seeds,
    build_signed_manifest,
    check_manifest,
    sign_capability_summary,
    sign_introduce_response,
    sign_manifest,
    sign_members_response,
    sign_query_response,
    sign_revocations_response,
    sign_result,
    verify_peer_request,
    verify_result,
)
```

Advanced primitives remain available from `federlet.lowlevel` for tests,
fixtures, and custom adapters:

```python
from federlet.lowlevel import (
    JWK,
    SignedRequest,
    b64u_decode,
    b64u_encode,
    build_signed_request,
    canonical_bytes,
    find_jwk,
    generate_key,
    public_jwk,
    public_key_from_jwk,
    sha256_hex,
    sign_dict,
    sign_model,
    verify_dict,
    verify_model,
    verify_signed_request,
)
```

The root `federlet` package re-exports the full public surface:

```python
from federlet import (
    AdmissionDecision,
    AdmissionPolicy,
    SeedBootstrapOutcome,
    SeedBootstrapReport,
    CapabilitySummary,
    Coverage,
    DiscoveryOutcome,
    DiscoveryRefreshReport,
    EvidenceVerifier,
    FederationClient,
    FederationNode,
    HealthResponse,
    IntroduceRequest,
    IntroduceResponse,
    JWK,
    KeyContinuityDecision,
    KeyContinuityPolicy,
    Manifest,
    ManifestLimits,
    ManifestRefreshDecision,
    ManifestVerificationError,
    MemberRecord,
    MemberRef,
    Membership,
    MembersResponse,
    MembershipTable,
    MissingCapabilitySummaryEndpointError,
    MissingRevocationsEndpointError,
    NonceCache,
    PeerHealthProbeResult,
    PeerState,
    ProtocolResponse,
    PublicKey,
    QueryCriteria,
    QueryRequest,
    QueryResponse,
    RateLimiter,
    ResultRef,
    ResultProvenance,
    RevocationNotice,
    RevocationsResponse,
    ResponseSignatureError,
    SIGNATURE_HEADER,
    SSRFError,
    Signature,
    SignedRequest,
    TokenBucketRateLimiter,
    UnauthorizedPeerRequest,
    VerifiedPeer,
    admit_manifest,
    apply_revocation_notice,
    bootstrap_from_seeds,
    build_signed_manifest,
    b64u_decode,
    b64u_encode,
    build_signed_request,
    canonical_bytes,
    check_key_continuity,
    check_manifest,
    disclose_members,
    domain_evidence_verifier,
    find_jwk,
    generate_key,
    probe_peer_health,
    public_jwk,
    public_key_from_jwk,
    refresh_discovered_members,
    refresh_peer_manifest,
    sha256_hex,
    sign_dict,
    sign_capability_summary,
    sign_introduce_response,
    sign_manifest,
    sign_members_response,
    sign_model,
    sign_query_response,
    sign_revocations_response,
    sign_result,
    verify_dict,
    verify_manifest,
    verify_model,
    verify_peer_request,
    verify_result,
    verify_response_signature,
    verify_revocation_notice,
    verify_signed_request,
)
```

The lower-level signing helpers are public so downstream tests and host
adapters can construct signed fixtures without importing `federlet.signing`
directly. Production request verification should still go through
`verify_peer_request`, which handles the raw header-to-identity flow. If a host
already has a parsed envelope and selected key, `verify_signed_request` remains
available for the lower-level target, method, path, body-hash, timestamp,
signature, and nonce checks.
