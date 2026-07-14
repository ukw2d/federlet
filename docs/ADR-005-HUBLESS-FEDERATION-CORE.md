# ADR-005: Hubless Federation Core

## 1. Status

**Proposed - federation architecture.**

This ADR defines a reusable, hubless federation protocol for independently
operated services. It standardizes signed peer identity, signed request and
response envelopes, peer admission, membership exchange, discovery hints,
manifest refresh, revocation, health probing, and generic operation envelopes.

It deliberately does not define host operation semantics, payload schemas,
aggregation policy, ranking, disclosure rules, projection formats, invocation
flows, persistence model, HTTP framework, or background scheduler.

The `federlet` Python package implements this protocol-library core. Host
products define their own profile: protocol identifiers, publication paths,
operation names, payload schemas, metadata, authorization, routing, and
application-specific discovery metadata.

## 2. Context

Multiple sovereign services need to discover each other and exchange signed,
auditable peer requests without making one runtime service, registry, or
published roster the center of the system.

The protocol must support:

1. **No central hub and no global membership list.** Each node maintains its own
   local view of accepted, rejected, stale, or unhealthy peers.
2. **Sovereign data ownership.** Each node owns its local state and decides what
   to disclose to each peer.
3. **Dynamic peer discovery.** Nodes can bootstrap from seed manifests,
   introduce themselves, exchange membership hints, refresh manifests, and
   converge on a useful local peer set.
4. **Production trust posture.** The design works with HTTPS, signed requests,
   key rotation, admission policy, audit, revocation, SSRF protection, NAT/proxy
   constraints, and change-control processes.
5. **Host semantics independence.** Federation standardizes envelopes and
   verification rules, not local operation meaning.

## 3. Decision

Adopt a hubless signed-manifest exchange model.

Each node:

- publishes a signed manifest at a stable, host-chosen URL;
- keeps a local membership table learned from seed peers, introductions, and
  membership exchange;
- validates every peer manifest and admission credential locally;
- serves federation APIs for membership exchange, introduction, operations,
  protocol, health, revocation, and any host-owned routes;
- authenticates peer requests with signed HTTP envelopes and/or host-selected
  transport authentication;
- executes host-owned operations from local policy and state;
- returns signed operation responses and, when needed, signed operation items
  with host-owned payloads.

There is no global roster. There is no central membership publisher. A seed peer
is an introducer, not an authority. Every node independently decides which peers
it accepts and what it discloses to them.

## 4. Scope

In scope:

- signed node manifests;
- seed-peer bootstrap;
- peer introduction;
- peer membership exchange;
- local admission and disclosure policy hooks;
- signed peer request authentication;
- generic operation request and response envelopes;
- signed operation item provenance;
- manifest refresh, revocation, health, and audit requirements.

Out of scope:

- host operation semantics;
- host payload schemas;
- local storage choice;
- aggregation and routing strategy;
- namespace authorization;
- principal mapping;
- central registry as the default design;
- DHT/libp2p routing.

### 4.1 Domain-neutrality invariant

The core is domain-agnostic and must stay that way. `federlet` never learns:

- **host path knowledge** — e.g. an `agent-directory.json` or `.well-known`
  path. A host resolves its own URLs and hands them to the library. The optional
  `well_known_url(base_url, path)` helper only joins a base with a
  caller-supplied path; it hardcodes no path of its own.
- **host operation names** — e.g. `directory.search`. The core carries an opaque
  `operation` string and never branches on its value.
- **downstream product identity** — the core names no host product.
- **enterprise auth semantics** — e.g. OIDC/JWKS token validation. The core
  ships `signed_http` and exposes hooks (`EvidenceVerifier`, auth-method
  verifiers) that a host uses to plug in its own auth methods.

A conformance test (`tests/test_neutrality.py`) scans the shipped package for a
denylist of tokens that would signal a regression of this invariant.

## 5. Manifest

A manifest is signed, node-owned coordinate data. It answers:

- who owns this node;
- where this node is reached;
- where this manifest is published, if the node chooses to advertise it;
- which protocol profile identifiers it supports;
- which public keys verify its signed requests and responses;
- which admission evidence it presents;
- which optional federation endpoints it exposes;
- which opaque host protocol metadata it wants to advertise.

Example:

```jsonc
{
  "node_id": "node:org-a:prod",
  "org_id": "org-a",
  "federations": ["example-federation-prod"],
  "endpoint": "https://node-a.example/federation/v1",
  "manifest_url": "https://node-a.example/manifest.json",
  "protocol_versions": ["example-federation/1"],
  "revision": 12,
  "public_keys": [
    {
      "key_id": "org-a-node-signing-2026-q3",
      "use": "sig",
      "alg": "EdDSA",
      "public_jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
    }
  ],
  "auth_methods": ["signed_http"],
  "membership": {
    "introduce_url": "https://node-a.example/federation/v1/members/introduce",
    "members_url": "https://node-a.example/federation/v1/members",
    "revocations_url": "https://node-a.example/federation/v1/revocations"
  },
  "extensions": {
    "example": {
      "operations_url": "https://node-a.example/federation/v1/operations",
      "profile_url": "https://node-a.example/profiles/example.json"
    }
  },
  "issued_at": "2026-07-01T10:00:00Z",
  "expires_at": "2026-07-08T10:00:00Z",
  "signature": {
    "key_id": "org-a-node-signing-2026-q3",
    "alg": "EdDSA",
    "sig": "..."
  }
}
```

`extensions` is opaque to federlet. Hosts use it to advertise profile metadata,
operation endpoints, schema URLs, or other application-owned coordinates.

`auth_methods` advertises how a peer can be authenticated. `signed_http` is the
built-in baseline (see section 7). Beyond it, the core interprets no method's
meaning: a host registers an auth-method verifier per advertised method it wants
to police (via `AdmissionPolicy.auth_method_verifiers`), and admission routes
each advertised method to the host's callback. Methods with no registered
verifier are left to host policy.

For `mtls`, the core ships a generic certificate-identity primitive
(`verify_certificate_identity`) that mechanically matches a host-presented
certificate identity against a host-supplied expected identity and binds it to
a host-chosen node_id. federlet ships no CA bundle, resolves no trust roots, and
never maps a certificate to a node itself — that policy stays with the host.

## 6. Operation envelopes

Federation standardizes a generic operation envelope. It does not standardize
operation names, payload schemas, metadata, routing, authorization, execution,
or aggregation.

### 6.1 Operation request

```jsonc
{
  "operation_id": "op-123",
  "operation": "example.lookup",
  "payload": {
    "text": "host-defined intent",
    "filters": {
      "topic": ["alpha"],
      "action": ["lookup"]
    }
  },
  "metadata": {
    "limit": 20,
    "timeout_ms": 2000,
    "routing_hint": "local-only"
  }
}
```

### 6.2 Operation response

```jsonc
{
  "operation_id": "op-123",
  "source_node_id": "node:org-c:prod",
  "payload": {
    "status": "ok"
  },
  "items": [
    {
      "payload": {
        "id": "item:org-c:example",
        "title": "Example payload"
      },
      "provenance": {
        "node_id": "node:org-c:prod",
        "content_hash": "sha256:..."
      },
      "signature": {
        "key_id": "org-c-node-signing-1",
        "sig": "..."
      }
    }
  ],
  "metadata": {
    "truncated": false
  },
  "signature": {
    "key_id": "org-c-node-signing-1",
    "sig": "..."
  }
}
```

The owning node may sign each `OperationItem` so downstream consumers can retain
provenance after aggregating payloads from many peers. The response envelope may
also be signed to authenticate the immediate peer response.

## 7. Security properties

- `signed_http` is the mandatory baseline peer authentication. Every manifest
  advertises it, admission requires it by default, and any additional auth
  method a host adds (e.g. mTLS certificate identity) layers on top of it —
  never replaces it. Its invariants (target/method/path/body binding, freshness,
  and nonce-claim-after-verify replay protection) are locked by
  `tests/test_signed_http_invariants.py`.
- A forged manifest fails signature verification.
- A stale or expired manifest can be rejected by local policy.
- A signed request cannot be replayed if the receiver uses a nonce cache.
- A signed request cannot be redirected to another node, method, path, or body.
- A signed operation item remains attributable to its owning node after
  aggregation.
- Manifest fetch and admission can reject private, loopback, link-local, and
  reserved endpoints by default.
- Admission evidence is host-defined and evaluated locally.
