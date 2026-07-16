# federlet

[![CI](https://github.com/ukw2d/federlet/actions/workflows/ci.yml/badge.svg)](https://github.com/ukw2d/federlet/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/federlet.svg)](https://pypi.org/project/federlet/)
[![Python versions](https://img.shields.io/pypi/pyversions/federlet.svg)](https://pypi.org/project/federlet/)
[![License](https://img.shields.io/pypi/l/federlet.svg)](https://github.com/ukw2d/federlet/blob/main/LICENSE)
[![Typed](https://img.shields.io/badge/typed-py.typed-blue.svg)](https://typing.python.org/en/latest/spec/distributing.html)
[![Ruff](https://img.shields.io/badge/lint-ruff-46a2f1.svg)](https://docs.astral.sh/ruff/)
[![mypy](https://img.shields.io/badge/types-mypy_checked-blue.svg)](https://mypy-lang.org/)

Federlet is an async Python library for decentralized, hubless federation
between peer services. It provides signed manifests, signed HTTP
requests, Ed25519 verification, replay protection, key-continuity checks, local
admission policy, SSRF-safe manifest fetching, health probing, revocations, and
peer discovery helpers.

Use federlet when independent services need zero-trust, service-to-service
federation without a central registry or control-plane hub. Your application
keeps control of HTTP routing, persistence, trust policy, key storage, semantic
operation semantics, observability, and deployment topology.

## At a glance

| Question | Answer |
| --- | --- |
| What is it? | A framework-neutral protocol library for peer service federation. |
| Trust model | Signed manifests, Ed25519 signed requests, local admission policy, and key-continuity checks. |
| Runtime | Async Python, `httpx`, Pydantic v2, structural protocols for host-owned storage. |
| Deployment shape | No central hub, no bundled server, no required cache backend. |
| Host responsibilities | HTTP routing, persistence, private-key storage, trust material, operation semantics, logging, metrics, and retries. |

## Features

federlet implements the protocol core from ADR-005:

- signed node manifests
- signed HTTP request envelopes for peer-to-peer calls
- Ed25519/JWK helpers and RFC 8785 canonical JSON signing
- freshness, clock-skew, target, method, path, body-hash, and replay checks
- local manifest admission policy and key-continuity checks
- SSRF protection for manifest URLs and admitted endpoints
- membership, revocation, manifest refresh, and discovery state helpers
- seed-bootstrap helpers
- optional stateful facade for common host workflows
- generic operation envelope models and signed operation-item helpers
- protocol, health, revocation, and membership client calls
- structural protocols for host-owned nonce caches, rate limiters, and services
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

Use federlet when independent services need to discover each other and make
signed, auditable requests without a central hub. Typical examples:

- two organizations already trust each other and want signed peer requests
- a new organization wants to join an existing federation through an introduction flow
- a service wants protocol semantics without adopting a bundled server framework

Do not use federlet as a complete federation server. It is the protocol library you
wire into your HTTP adapter, worker, or service runtime.

federlet deliberately does not implement host operations, payload schemas,
fan-out, coverage calculation, principal mapping, namespace authorization, or
application policy. Those belong to the host application.

## Core concepts

| Concern | federlet provides | Your application provides |
| --- | --- | --- |
| Manifests | Pydantic wire models, fetch-time verification, signing, freshness checks | key lifecycle, publication URL, revision policy |
| Signed requests | envelope creation and verification | request routing and response handling |
| Replay protection | `NonceCache` protocol and nonce-claim logic | the cache object passed at verification time |
| Rate limiting | async `RateLimiter` protocol and in-memory `TokenBucketRateLimiter` | distributed per-peer limiter state |
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
  `sign_operation_response`.
- Operation-envelope flows: parse `OperationRequest` in your application,
  execute host-owned logic, then return an `OperationResponse` with signed
  `OperationItem` payloads when per-item provenance matters.

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
        node_id="node:org-a:prod",
        org_id="org-a",
        endpoint="https://node-a.example/federation/v1",
        federations=["example-federation-prod"],
        protocol_versions=["example-federation/1"],
        manifest_url="https://node-a.example/manifest.json",
    )
    manifest_b = build_signed_manifest(
        key_b,
        "org-b-k1",
        node_id="node:org-b:prod",
        org_id="org-b",
        endpoint="https://node-b.example/federation/v1",
        federations=["example-federation-prod"],
        protocol_versions=["example-federation/1"],
        manifest_url="https://node-b.example/manifest.json",
    )

    decision = await admit_manifest(
        manifest_b,
        AdmissionPolicy(
            federation_id="example-federation-prod",
            protocol_versions={"example-federation/1"},
        ),
    )
    assert decision.accepted, decision.reason

    body = b'{"operation":"example"}'
    envelope = build_signed_request(
        key_a,
        "org-a-k1",
        federation_id="example-federation-prod",
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
async `RateLimiter` protocol (`await allow(peer_node_id, now=...)`).
`TokenBucketRateLimiter` is an in-memory reference implementation that reads
`Manifest.limits.max_operation_rps_per_peer`; production deployments should keep
the bucket state in Redis, Valkey, or an equivalent shared store.

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
    federation_id="example-federation-prod",
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
    node_id="node:org-a:prod",
    federation_id="example-federation-prod",
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
| `federlet.publication` | Convenience builder for signed node manifests. |
| `federlet.node` | Optional stateful facade over the functional protocol core. |
| `federlet.models` | Pydantic wire models for manifests, introductions, membership, signatures, and signed request envelopes. |
| `federlet.crypto` | Ed25519/JWK conversion, base64url helpers, and RFC 8785 canonical JSON bytes. |
| `federlet.signing` | Manifest signing/checking and signed request construction/verification. |
| `federlet.audit` | Pure audit record builder for host logging sinks. |
| `federlet.admission` | Local manifest admission checks and host-supplied evidence verifier protocol. |
| `federlet.membership` | Membership state model (`MemberRecord`), federlet-owned admission/backoff/eligibility policy functions, and `MembershipTable` (in-memory reference store). Durable persistence is host-owned. |
| `federlet.refresh` | One-shot manifest refresh and key-continuity decision helper. |
| `federlet.discovery` | Bounded peer discovery from signed membership hints. |
| `federlet.health` | Protocol and health probe classification helpers. |
| `federlet.operations` | Generic operation request/response envelopes and signed operation-item helpers. |
| `federlet.fanout` | Generic concurrent operation fan-out over selected peers with a structured per-peer success/failure report. |
| `federlet.certauth` | Generic certificate-identity (mTLS) auth primitive; trust roots and cert-to-peer mapping stay host-owned. |
| `federlet.urls` | `well_known_url` joiner for caller-supplied base and path; federlet hardcodes no paths. |
| `federlet.net` | SSRF guard for manifest and endpoint URLs. |
| `federlet.client` | Async `httpx` helpers for manifest fetch, introduction, members, revocations, protocol, health, and operation calls. |
| `federlet.protocols` | Structural protocols such as `NonceCache`, async `RateLimiter`, async `MembershipStore`, and async `ManifestStore` for redis/SQL/Valkey-backed hosts. |

## Membership durability

federlet keeps a functional core and pushes all persistence to the host. Two
concerns split cleanly:

- **Storage is a host-owned async port.** `MembershipStore` is a thin CRUD
  interface — `await get(node_id)`, `await upsert(record)`, `await values()`,
  and `await delete(node_id)`. A host backs it with redis, SQL, Valkey, or a JSON
  file in roughly ten lines. `MembershipTable` is the optional in-memory
  reference implementation (a default and test double); it is *not* required and
  holds no policy.
- **Policy is federlet-owned.** Admission, exponential backoff, and eligibility
  are pure functions — `admit`, `record_success`, `record_failure` (with
  `CooldownPolicy`), `set_state`, and `eligible_peers` — that federlet applies
  over records read from and written back to your store. Adapters never
  reimplement the state machine; they persist `MemberRecord`, which is a Pydantic
  model that round-trips through `model_dump(mode="json")` / `model_validate`.

The application-facing pattern is always read → apply policy → persist:

```python
rec = await store.get(node_id)
if rec is not None:
    await store.upsert(record_failure(rec, cooldown_policy))
```

### Manifest persistence

Manifest durability is intentionally asymmetric with membership durability:

- `MembershipStore` is the cold working set for membership state.
- `ManifestStore` is an async write-through sink plus a startup hydration source.
  It has `upsert(manifest)`, `delete(node_id)`, and `values()`, but no point-wise
  `get`.

Inbound verification (`verify_known_inbound`) stays on the hot in-memory
`peer_manifests` map; it never calls the durable store. If you pass
`manifest_store=...` to `FederationNode`, admitted/refreshed manifests are
persisted write-through, refresh rejects and trusted revocations evict them from
both cache and store, and `async with FederationNode(...)` calls `hydrate()` to
populate an empty cache from `await manifest_store.values()` at startup.

Hosts that do not use the context manager can call `await node.hydrate()` before
serving inbound requests. Plakard-style adapters can implement both ports on one
backend:

```python
store = build_peer_store(cfg.peer_store)
node = FederationNode(..., membership_table=store, manifest_store=store)
await node.hydrate()
```

For Plakard x39, pin `federlet>=0.6` and implement one async cashews-backed
adapter for both `MembershipStore` and `ManifestStore`.

### Revocation trust model

`apply_revocation_notice` (and the `FederationNode.apply_revocation_notice`
facade) applies a notice only after **two independent gates** pass:

1. **Cryptographic authenticity** — `trusted_issuer_keys` +
   `verify_revocation_notice` prove the notice was signed by a key the caller
   trusts. The caller is responsible for ensuring a `key_id` in
   `trusted_issuer_keys` genuinely belongs to the claimed `issuer`/authority;
   federlet maintains no key-to-identity registry.
2. **Semantic authorization** — an `authorize: Callable[[RevocationNotice], bool]`
   predicate decides whether this `issuer` is allowed to revoke this
   `revoked_node_id`. It defaults to `self_scoped_authorize`, which requires
   `issuer == revoked_node_id` (the safe behavior a host gets without supplying
   any policy).

The default is deliberately restrictive: a cross-node notice (`issuer !=
revoked_node_id`) is **rejected even with a valid signature**. This stops a
compromised peer from forging a notice about another node. To enable
**cross-authority revocation** — the only way to evict a compromised or hostile
node that will never self-revoke — pass an `authorize` closure built from your
own authority config:

```python
async def revoke_compromised(node, authority_key, peer_id):
    notice = build_revocation(
        revoked_node_id=peer_id,
        issuer=authority_key.node_id,
        federation_id=node.federation_id,
        key=authority_key.private_key,
        key_id=authority_key.key_id,
        reason="compromised",
    )
    return await node.apply_revocation_notice(
        notice,
        trusted_issuer_keys=authority_key.trusted_keys,
        authorize=lambda n: n.issuer in my_authorities,  # host-owned policy
    )
```

federlet **never defines what "authority" or "scope" means** — no federation
vs. org taxonomy, no authority registry, no config. The host builds the
`authorize` closure; federlet only calls it. Use `build_self_revocation` for
the common cooperative-departure case and `build_revocation` for the
cross-authority case; both produce signed notices that round-trip through
`verify_revocation_notice` and `apply_revocation_notice`.

## Usage scenarios

### Scenario: existing peers exchange membership

1. Org A and Org B exchange signed manifest URLs through an existing trust path.
2. Each service fetches and verifies the other's manifest.
3. Each service admits the peer with its local `AdmissionPolicy`.
4. Org A calls `get_members(org_b_manifest)`.
5. Org B verifies the signed request and signs the membership response.
6. Org A verifies the response signature and treats returned members as discovery hints.

This is the simplest steady-state deployment. No central hub is required.

### Scenario: a new peer joins

1. Org C starts with one or more seed manifest URLs for the federation.
2. Org C calls `bootstrap_from_seeds`, which fetches/verifies each seed
   manifest, applies local admission policy, and sends a signed introduction.
4. Each seed peer admits or rejects Org C independently.
5. Org C calls `get_members` to learn additional manifest URLs.
6. The host may include Org C in its own operation routing layer once local membership state marks it active.

The integration test in `tests/test_federation.py` exercises this flow with
three local nodes.

### Scenario: a peer is slow or unhealthy

1. The host probes or calls eligible peers on its own schedule.
2. The host records timeouts and transport failures.
3. `MembershipTable` can model cooldown for repeatedly failing peers.
4. A later host-observed success moves the peer back to active.

This keeps local peer selection useful during partial outages without making
federlet own a background scheduler.

### Scenario: a peer returns operation payloads

1. The host receives a signed operation request and authenticates it with
   `verify_peer_request`.
2. The host parses `OperationRequest`; authorization, execution, aggregation,
   and response metadata stay in the host.
3. The host returns an `OperationResponse` containing signed `OperationItem`
   payloads when individual payload provenance matters.
4. Downstream hosts can aggregate payloads from many peers and still verify each
   item's provenance with `verify_operation_item`.

## Production notes

- Store private keys in your platform key manager or secret service, not in code.
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
- revocation, health, refresh, and discovery flows

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

## Migrating to the operation API

Version `0.4.0` separates federlet core from host application protocols.
Federlet now signs and verifies generic operation envelopes; host packages own
their request, response, metadata, and discovery models.

Replace imports and calls as follows:

| Before | After |
| --- | --- |
| `QueryRequest` | `OperationRequest` |
| `QueryResponse` | `OperationResponse` |
| `ResultRef` / `FederatedResult` | `OperationItem` |
| `ResultProvenance` | `PayloadProvenance` |
| `sign_query_response` | `sign_operation_response` |
| `sign_result` | `sign_operation_item` or `sign_operation_payload` |
| `verify_result` | `verify_operation_item` |
| `Manifest.capability_summary_url` | `Manifest.extensions` |
| `CapabilitySummary` / `sign_capability_summary` | host-owned models/helpers |

Move host-owned criteria, limits, coverage, ranking, fetch references, and
profile discovery metadata into operation payloads, operation metadata, item
payloads, or manifest extensions.

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
    OperationItem,
    OperationRequest,
    OperationResponse,
    PayloadProvenance,
    PublicKey,
    SIGNATURE_HEADER,
    SeedBootstrapReport,
    UnauthorizedPeerRequest,
    admit_manifest,
    bootstrap_from_seeds,
    build_operation_item,
    build_signed_manifest,
    check_manifest,
    sign_introduce_response,
    sign_manifest,
    sign_members_response,
    sign_operation_item,
    sign_operation_payload,
    sign_operation_response,
    sign_revocations_response,
    verify_peer_request,
    verify_operation_item,
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
    MissingRevocationsEndpointError,
    NonceCache,
    OperationItem,
    OperationRequest,
    OperationResponse,
    PayloadProvenance,
    PeerHealthProbeResult,
    PeerState,
    ProtocolResponse,
    PublicKey,
    RateLimiter,
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
    build_operation_item,
    build_revocation,
    build_self_revocation,
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
    self_scoped_authorize,
    sha256_hex,
    sign_dict,
    sign_introduce_response,
    sign_manifest,
    sign_members_response,
    sign_model,
    sign_operation_item,
    sign_operation_payload,
    sign_operation_response,
    sign_revocations_response,
    verify_dict,
    verify_manifest,
    verify_model,
    verify_operation_item,
    verify_peer_request,
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
