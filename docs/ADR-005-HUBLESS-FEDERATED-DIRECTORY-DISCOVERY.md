# ADR-005: Hubless Federation Discovery

## 1. Status

**Proposed - federation architecture.**

This ADR defines a reusable, hubless federation protocol for independently
operated services. It standardizes signed peer identity, signed request
envelopes, peer admission, membership exchange, discovery hints, query/response
envelopes, result-reference provenance, and optional capability summaries.

It deliberately does not define a host record schema, local search engine,
ranking algorithm, record projection format, invocation flow, persistence model,
HTTP framework, or background scheduler.

The `federlet` Python package implements this universal protocol-library core.
Host products define their own profile: protocol identifier, manifest
publication path, record vocabulary, query semantics, result attributes, and
capability facets.

## 2. Context

Multiple sovereign services need to discover each other and exchange signed,
auditable peer requests without making one runtime service, registry, or
published roster the center of the system.

The protocol must support:

1. **No central hub and no global membership record.** Each node maintains its
   own local view of accepted, rejected, stale, or unhealthy peers.
2. **Sovereign data ownership.** Each node owns its local records and decides
   what to disclose to each peer.
3. **Dynamic peer discovery.** Nodes can bootstrap from seed manifests, introduce
   themselves, exchange membership hints, refresh manifests, and converge on a
   useful local peer set.
4. **Production trust posture.** The design works with HTTPS, signed requests,
   key rotation, admission policy, audit, revocation, SSRF protection, NAT/proxy
   constraints, and change-control processes.
5. **Host semantics independence.** Federation standardizes envelopes and
   verification rules, not local search or record meaning.

## 3. Decision

Adopt a hubless signed-manifest exchange model.

Each node:

- publishes a signed manifest at a stable, host-chosen URL;
- keeps a local membership table learned from seed peers, introductions, and
  membership exchange;
- validates every peer manifest and admission credential locally;
- serves federation APIs for membership exchange, introduction, query, optional
  record fetch, protocol, health, revocation, and capability summary;
- authenticates peer requests with signed HTTP envelopes and/or host-selected
  transport authentication;
- answers query requests from its own local data only;
- returns signed lightweight result references;
- serves full records only through explicit authenticated host routes.

There is no global roster. There is no central membership publisher. A seed peer
is an introducer, not an authority. Every node independently decides which peers
it accepts and what it discloses to them.

## 4. Scope

In scope:

- signed node manifests;
- seed-peer bootstrap;
- peer introduction;
- peer membership exchange;
- local admission and disclosure policy;
- signed peer request authentication;
- query and response envelopes;
- result-reference signing and provenance;
- optional capability summaries;
- liveness, revocation, refresh, rollout, and audit requirements.

Out of scope:

- local storage choice;
- local ranking/search implementation;
- host record schema;
- record projection formats;
- request fan-out strategy;
- namespace authorization;
- principal mapping;
- central registry as the default design;
- DHT/libp2p routing.

## 5. Architecture overview

```text
                         HUBLESS FEDERATION NETWORK

      ┌──────────────────────┐                  ┌──────────────────────┐
      │ Node A               │                  │ Node B               │
      │ Org A                │                  │ Org B                │
      │ local records        │                  │ local records        │
      │ local member table   │                  │ local member table   │
      │ signed manifest      │                  │ signed manifest      │
      └──────────┬───────────┘                  └──────────┬───────────┘
                 │ introduce / members / query / fetch      │
                 ├──────────────────────────────────────────►│
                 │◄──────────────────────────────────────────┤
                 │ signed manifests / references / records   │
                 │                                           │
      ┌──────────▼───────────┐                  ┌────────────▼─────────┐
      │ Node C               │                  │ Node D               │
      │ Org C                │                  │ Org D                │
      └──────────────────────┘                  └──────────────────────┘

      Each node owns its own manifest and records.
      Membership is learned by peer exchange and stored locally at each node.
```

The local requester talks to its own node. That node decides which peers to query
based on its local membership table, peer manifests, disclosure policy, health
state, and optional capability summaries.

## 6. Federation entities

### 6.1 Node

A node is an independently operated service instance. It has:

- a stable `node_id`;
- an owning `org_id` and optional `bu_id`;
- a federation API endpoint;
- a host-chosen manifest URL;
- one or more public verification keys;
- local records;
- a local membership table;
- local policy for peer admission and disclosure.

### 6.2 Federation

A federation is a named trust context. There is no single federation membership
file. The federation is the convergent set of nodes that mutually accept each
other's signed manifests and admission evidence under the same `federation_id`.

### 6.3 Manifest

A manifest is signed, node-owned coordinate data. It answers:

- who owns this node;
- where this node is reached;
- where this manifest is published, if the node chooses to advertise it;
- which protocol profile identifiers it supports;
- which public keys verify its signed requests and responses;
- which admission evidence it presents;
- which optional protocol endpoints it exposes.

Example:

```jsonc
{
  "node_id": "node:org-a:prod",
  "org_id": "org-a",
  "bu_id": "business-unit-a",
  "federations": ["supplier-network-prod"],
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
  "capability_summary_url": "https://node-a.example/federation/v1/capability",
  "issued_at": "2026-07-01T10:00:00Z",
  "expires_at": "2026-07-08T10:00:00Z",
  "signature": {
    "key_id": "org-a-node-signing-2026-q3",
    "alg": "EdDSA",
    "sig": "..."
  }
}
```

The manifest URL is explicit host data. The protocol core does not derive a
publication path from any endpoint.

### 6.4 Local membership table

Each node maintains a local cache of peers this node has learned, validated,
admitted, rejected, or marked unhealthy.

```jsonc
{
  "node_id": "node:org-c:prod",
  "org_id": "org-c",
  "manifest_url": "https://node-c.example/manifest.json",
  "manifest_revision": 7,
  "state": "active",
  "admission": "accepted",
  "accepted_until": "2026-07-08T10:00:00Z",
  "last_manifest_refresh": "2026-07-01T10:05:00Z",
  "last_protocol_ok": "2026-07-01T10:05:05Z"
}
```

## 7. Admission

A node accepts a manifest only if local policy permits it. Common checks include:

- the manifest signature is valid;
- the manifest is fresh enough;
- the requested federation is present;
- at least one supported protocol identifier overlaps local policy;
- endpoint and advertised URLs satisfy local SSRF and allowlist rules;
- admission evidence passes host-defined validation.

DNS-domain evidence is one possible admission evidence shape. In federlet,
`DomainProofEvidence` and `allowed_endpoint_domains` refer to DNS endpoint
ownership, not host record categories or capability facets.

## 8. Signed request envelope

Peer requests are authenticated with a signed envelope carried in a header such
as `X-Federlet-Signature`.

```jsonc
{
  "federation_id": "supplier-network-prod",
  "request_id": "req-7f7f",
  "source_node_id": "node:org-a:prod",
  "target_node_id": "node:org-b:prod",
  "method": "GET",
  "path": "/federation/v1/members",
  "body_sha256": "sha256:e3b0c442...",
  "timestamp": "2026-07-01T10:00:00Z",
  "nonce": "01J...",
  "source_manifest_revision": 12,
  "signature": {
    "key_id": "org-a-node-signing-2026-q3",
    "alg": "EdDSA",
    "sig": "..."
  }
}
```

The receiver validates source membership, key lookup, target node, method, path,
body hash, freshness, nonce replay, and signature.

For `POST /members/introduce`, the source may not yet be accepted. In that one
case, the receiver verifies the request envelope against the public key in the
embedded manifest, then applies normal admission policy.

## 9. Bootstrap and membership exchange

Bootstrap starts from one or more seed manifest URLs:

```yaml
seed_manifest_urls:
  - https://node-a.example/manifest.json
  - https://node-b.example/manifest.json
```

The joining node fetches each seed manifest, verifies it, applies local admission
policy, then sends a signed introduction request containing its own manifest and
explicit manifest URL.

Membership exchange returns signed `MemberRef` hints. A node that receives a
hint still fetches, verifies, and admits that peer under local policy before
treating it as eligible.

## 10. Query protocol

Federation standardizes the query envelope. It does not standardize how a node
interprets query criteria or searches local data.

### 10.1 Query request

```jsonc
{
  "query_id": "q-123",
  "query": {
    "text": "records matching a host-defined intent",
    "filters": {
      "topic": ["finance"],
      "operation": ["invoice.reconcile"],
      "record_type": "workflow"
    }
  },
  "requested_fields": ["record_id", "title", "description", "facets"],
  "limit": 20,
  "timeout_ms": 2000,
  "disclosure_context": {
    "requester_org": "org-a",
    "purpose": "procurement-workflow"
  }
}
```

`query`, `filters`, `requested_fields`, and `disclosure_context` are host-owned
semantics carried by a standard envelope.

### 10.2 Query response

```jsonc
{
  "query_id": "q-123",
  "source_node_id": "node:org-c:prod",
  "results": [
    {
      "record_id": "record:org-c:invoice-workflow",
      "fetch_url": "https://node-c.example/federation/v1/records/record:org-c:invoice-workflow",
      "revision": 17,
      "attributes": {
        "record_type": "workflow",
        "title": "Invoice reconciliation workflow",
        "description": "Reconciles invoices against purchase orders.",
        "facets": {
          "topic": ["finance"],
          "operation": ["invoice.reconcile"]
        }
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
  "coverage": {
    "searched_local_catalogue": true,
    "filtered_by_visibility": true,
    "truncated": false
  },
  "signature": {
    "key_id": "org-c-node-signing-1",
    "sig": "..."
  }
}
```

The owning node signs each `ResultRef` so downstream consumers can retain
provenance after merging results from many peers. The response envelope may also
be signed to authenticate the immediate peer response.

`ResultRef.attributes` is host-owned, disclosure-filtered data. Federation
defines only the signed reference shape and provenance checks.

## 11. Fetch protocol

Query returns lightweight result references. Full records are fetched explicitly
from the owning node using host-defined routes and projection formats.

The owning node must re-check authorization on fetch. Permission to see a
lightweight result reference does not imply permission to fetch the full record
or a sensitive projection.

## 12. Capability summary

A node may publish a coarse capability summary to help peers decide whether
querying it is worth the latency. This is an optimization, not the source of
truth.

```jsonc
{
  "node_id": "node:org-c:prod",
  "summary_version": 5,
  "record_types": ["workflow"],
  "facets": {
    "topic": ["finance", "procurement"],
    "operation": ["invoice.reconcile", "supplier.lookup"]
  },
  "coverage_text": "Supplier, invoice, and procurement workflow records.",
  "updated_at": "2026-07-01T10:00:00Z",
  "expires_at": "2026-07-08T10:00:00Z",
  "signature": {
    "key_id": "org-c-node-signing-1",
    "sig": "..."
  }
}
```

Rules:

- summaries are signed by the owning node;
- summaries are coarse and must not reveal private records;
- summaries are advisory only;
- low confidence should fall back to querying more peers;
- correctness must not depend on perfect summary scoring.

`facets` is a host-owned dictionary. Federation does not define facet names.

## 13. Revocation, refresh, health, and audit

Nodes should refresh accepted peer manifests, probe protocol and health
endpoints, apply signed revocation notices from trusted issuers, and audit
admission, rejection, signature failure, revocation, refresh, and disclosure
events.

These workflows are local state transitions. They do not create a global
membership authority.

## 14. Security properties

- A forged manifest fails signature verification.
- A stale or expired manifest can be rejected by local policy.
- A signed request cannot be replayed if the receiver uses a nonce cache.
- A signed request cannot be redirected to another node, method, path, or body.
- A result reference remains attributable to its owning node after merging.
- Manifest fetch and admission can reject private, loopback, link-local, and
  reserved endpoints by default.
- Admission evidence is host-defined and evaluated locally.

## 15. Plakard profile appendix

This appendix records one host profile that can be layered on the universal
federation core. These names are not part of federlet's core model API.

Plakard may choose:

- protocol identifier: `agent-directory-federation/1`;
- manifest publication path: `/.well-known/agent-directory.json`;
- record attribute vocabulary inside `ResultRef.attributes`:
  - `record_type`;
  - `name`;
  - `summary`;
  - `owner_org`;
  - `domains`;
  - `skills`;
- capability facets inside `CapabilitySummary.facets`:
  - `domains`;
  - `skills`;
- fetch projections such as OASF records, A2A cards, DID references, or other
  Plakard-owned formats.

Migration from the previous core shape:

- `ResultCard` becomes `ResultRef`;
- typed result fields move under `ResultRef.attributes`;
- `sign_result_card` becomes `sign_result`;
- `verify_result_card` becomes `verify_result`;
- typed `CapabilitySummary.domains` and `CapabilitySummary.skills_top` move to
  host-owned entries in `CapabilitySummary.facets`;
- federlet no longer provides a default protocol identifier;
- federlet no longer derives a manifest URL from a membership endpoint.
