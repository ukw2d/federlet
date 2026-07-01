# ADR-005: Hubless Federated Directory Discovery

## 1. Status

**Proposed - federation architecture.** This ADR defines how multiple sovereign directory
instances discover each other, authenticate each other, exchange discovery requests, and fetch
directory records across Business Units (BUs) or organizations **without a central membership
record, central runtime hub, DHT, or mandatory SWIM cluster**.

This ADR deliberately does **not** define the local catalogue schema, local search engine,
vector index, card serialization, or agent invocation flow:

- **ADR-003** owns the local directory node: canonical OASF-based records, local search,
  projections, serializer invariants, and storage/index choices.
- **ADR-004** owns post-card agent access: direct invocation, gateway-mediated invocation,
  credentials, target auth, and egress authorization.
- **ADR-005** owns only federation across directory instances.

## 2. Context

We need many directory instances to participate in one discovery network without making any
single runtime service or signed global file the center of the system.

The directory records are OASF-based documents. A node may be operated by:

- one BU inside a large enterprise;
- one subsidiary or region;
- one partner organization;
- one independent external organization.

A requester should be able to ask its local directory for records matching an intent/filter and
receive candidates from all directory instances it has discovered and is allowed to query. The
requester should not need to know which BU or organization owns the record before searching.

The non-negotiable requirements are:

1. **No central hub and no central membership record.** No service, registry, roster file, or
   publisher is the global source of truth for who exists.
2. **Sovereign data ownership.** Each directory owns and serves its own records. Foreign records
   are pulled on demand, not bulk-replicated by default.
3. **Dynamic peer discovery.** Nodes can introduce themselves, learn peers from peers, refresh
   manifests, and converge on a useful membership view without redeploying every participant.
4. **Enterprise production posture.** The design must work with HTTPS, mTLS or signed requests,
   allowlists, audit, revocation, NAT/proxy constraints, and change-control processes.
5. **Search capability independence.** A node may implement vector search, keyword search,
   relational filters, or other local retrieval methods. Federation standardizes request and
   response envelopes, not the local search implementation.

## 3. Decision

Adopt a **hubless signed-manifest exchange** model.

Each node:

- publishes a signed **node manifest** at a stable well-known URL;
- keeps a local membership table learned from seed peers, introductions, and peer membership
  exchange;
- validates every peer manifest and admission credential locally;
- serves HTTPS federation APIs for membership exchange, query, fetch, protocol, and health;
- authenticates peer requests with mTLS and/or signed HTTP requests;
- answers discovery requests from its own local catalogue only;
- returns signed lightweight result cards;
- serves full records only through explicit authenticated fetch requests.

There is no global roster. There is no central membership publisher. A seed peer is only an
introducer, not an authority. Every node independently decides which discovered peers it accepts
and what it discloses to them.

## 4. Scope

**In scope:**

- self-published node manifests;
- seed-peer bootstrap;
- peer introduction;
- peer membership exchange;
- local admission and disclosure policy;
- cross-node request authentication;
- query and fetch request/response envelopes;
- result signing and provenance;
- liveness, revocation, rollout, and audit requirements;
- comparison with SWIM and other options.

**Out of scope:**

- local storage choice: Qdrant, Postgres/pgvector, MongoDB, Vespa, etc.;
- local ranking/search algorithm;
- embedding model selection;
- canonical record schema and serializers;
- gateway invocation;
- target-agent OAuth/DID/token flows;
- central registry/roster as the default design;
- DHT/libp2p routing.

## 5. Architecture Overview

```
                         HUBLESS FEDERATED DIRECTORY NETWORK

      ┌──────────────────────┐                  ┌──────────────────────┐
      │ Directory Node A     │                  │ Directory Node B     │
      │ BU / Org A           │                  │ BU / Org B           │
      │                      │                  │                      │
      │ local OASF records   │                  │ local OASF records   │
      │ local member table   │                  │ local member table   │
      │ signed manifest      │                  │ signed manifest      │
      └──────────┬───────────┘                  └──────────┬───────────┘
                 │ introduce / members / query / fetch      │
                 ├──────────────────────────────────────────►│
                 │◄──────────────────────────────────────────┤
                 │ signed manifests/cards/records            │
                 │                                           │
      ┌──────────▼───────────┐                  ┌────────────▼─────────┐
      │ Directory Node C     │                  │ Directory Node D     │
      │ BU / Org C           │                  │ Partner / Org D      │
      └──────────────────────┘                  └──────────────────────┘

      Each node owns its own manifest and records.
      Membership is learned by peer exchange and stored locally at each node.
```

The local requester talks to its own node. That local node decides which peers to query based on
its local membership table, peer manifests, disclosure policy, health state, and optional
capability summaries.

## 6. Federation Entities

### 6.1 Directory Node

A node is an independently operated directory instance. It has:

- a stable `node_id`;
- an owning `org_id` and optional `bu_id`;
- a federation endpoint;
- one or more public verification keys;
- a well-known manifest URL;
- local catalogue records;
- a local membership table;
- local policy for which peers it admits and what it discloses to each peer.

### 6.2 Federation

A federation is a named trust domain for directory nodes.

Examples:

- `epam-internal-agents-prod`
- `supplier-network-prod`
- `regulated-partner-poc`

There is no single federation membership file. The federation is the convergent set of nodes
that mutually accept each other's signed manifests and admission evidence under the same
`federation_id`.

### 6.3 Node Manifest

A manifest is signed node-owned coordinate data. It answers:

- who owns this node;
- where this node is reached;
- which protocol versions it supports;
- which public keys verify its signed requests/responses;
- which admission credentials or domain proofs it presents;
- how other nodes should refresh its current state.

### 6.4 Local Membership Table

Each node maintains its own local membership table. This is not a replicated global database. It
is a local cache of peers this node has learned, validated, admitted, rejected, or marked
unhealthy.

Example local table row:

```jsonc
{
  "node_id": "dir:org-c:prod",
  "org_id": "org-c",
  "manifest_url": "https://dir.org-c.example/.well-known/agent-directory.json",
  "manifest_revision": 7,
  "state": "active",
  "admission": "accepted",
  "accepted_until": "2026-07-08T10:00:00Z",
  "last_manifest_refresh": "2026-07-01T10:05:00Z",
  "last_protocol_ok": "2026-07-01T10:05:05Z"
}
```

## 7. Node Manifest

Each node publishes a signed manifest at a stable well-known URL:

```text
https://dir.org-a.example/.well-known/agent-directory.json
```

Example:

```jsonc
{
  "node_id": "dir:org-a:prod",
  "org_id": "org-a",
  "bu_id": "finance",
  "federations": ["supplier-network-prod"],
  "endpoint": "https://dir.org-a.example/federation/v1",
  "protocol_versions": ["agent-directory-federation/1"],
  "revision": 12,
  "public_keys": [
    {
      "key_id": "org-a-node-signing-2026-q3",
      "use": "sig",
      "alg": "EdDSA",
      "public_jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
    }
  ],
  "auth_methods": ["signed_http", "mtls"],
  "membership": {
    "introduce_url": "https://dir.org-a.example/federation/v1/members/introduce",
    "members_url": "https://dir.org-a.example/federation/v1/members",
    "revocations_url": "https://dir.org-a.example/federation/v1/revocations"
  },
  "capability_summary_url": "https://dir.org-a.example/federation/v1/capability-summary",
  "admission_evidence": {
    "type": "domain_proof",
    "domain": "org-a.example"
  },
  "disclosure": {
    "default": "federation",
    "supports_partner_scopes": true
  },
  "limits": {
    "max_query_rps_per_peer": 5,
    "max_query_timeout_ms": 3000,
    "max_results": 50
  },
  "issued_at": "2026-07-01T10:00:00Z",
  "expires_at": "2026-07-08T10:00:00Z",
  "signature": {
    "key_id": "org-a-node-signing-2026-q3",
    "sig": "..."
  }
}
```

A receiving node validates:

- manifest signature;
- manifest freshness;
- `node_id` stability;
- domain proof or admission credential;
- supported `federation_id`;
- protocol compatibility;
- endpoint host/IP policy;
- key continuity or allowed rotation.

## 8. Membership Discovery

### 8.1 Bootstrap with Seed Peers

A new node needs one or more seed peers. A seed peer is simply a known starting point.

Example bootstrap config:

```yaml
local_node_id: dir:org-c:prod
federation_id: supplier-network-prod
seed_manifest_urls:
  - https://dir.org-a.example/.well-known/agent-directory.json
  - https://dir.org-b.example/.well-known/agent-directory.json
trusted_admission_issuers:
  - supplier-network-charter-key-2026
```

Seed peers are not a hub and not an authority. If a seed peer disappears, the node can continue
using already learned peers and can bootstrap from any other known peer.

### 8.2 Introduction

A node introduces itself to a peer with:

```text
POST /federation/v1/members/introduce
```

Request:

```jsonc
{
  "federation_id": "supplier-network-prod",
  "manifest_url": "https://dir.org-c.example/.well-known/agent-directory.json",
  "manifest": {
    "...": "signed Org C manifest"
  },
  "requested_disclosure": "federation",
  "nonce": "base64...",
  "timestamp": "2026-07-01T10:00:00Z",
  "signature": {
    "key_id": "org-c-node-signing-1",
    "sig": "..."
  }
}
```

Response:

```jsonc
{
  "accepted": true,
  "accepted_node_id": "dir:org-c:prod",
  "accepted_manifest_revision": 1,
  "accepted_until": "2026-07-08T10:00:00Z",
  "membership_cursor": "m-1842",
  "known_peer_count": 14,
  "signature": {
    "key_id": "org-a-node-signing-2026-q3",
    "sig": "..."
  }
}
```

Acceptance means only: "this peer accepts your node under its local policy." It does not force
any other node to accept the newcomer.

### 8.3 Membership Exchange

Accepted peers can ask each other for known peers:

```text
GET /federation/v1/members?since=m-1842
```

Response:

```jsonc
{
  "source_node_id": "dir:org-a:prod",
  "cursor": "m-1850",
  "members": [
    {
      "node_id": "dir:org-b:prod",
      "org_id": "org-b",
      "manifest_url": "https://dir.org-b.example/.well-known/agent-directory.json",
      "manifest_revision": 9,
      "disclosure": "federation"
    },
    {
      "node_id": "dir:org-d:prod",
      "org_id": "org-d",
      "manifest_url": "https://dir.org-d.example/.well-known/agent-directory.json",
      "manifest_revision": 3,
      "disclosure": "partner:org-c"
    }
  ],
  "signature": {
    "key_id": "org-a-node-signing-2026-q3",
    "sig": "..."
  }
}
```

The receiver does not blindly trust the returned list. For each learned peer, it fetches the
peer's manifest directly from the owning domain and runs local admission checks.

### 8.4 Direct Manifest Refresh

Nodes periodically refresh accepted peers directly:

```text
GET https://dir.org-b.example/.well-known/agent-directory.json
```

This detects endpoint changes, key rotation, expiry, and revocation pointers without relying on
the original introducer.

### 8.5 Revocation

There is no global revocation list by default. Revocation is handled through:

- the revoked node's own manifest disappearing or declaring `state: revoked`;
- direct trust-policy denylist at each node;
- signed revocation notices exchanged through `/revocations`;
- admission credential expiry;
- manual local operator action.

Example revocation notice:

```jsonc
{
  "federation_id": "supplier-network-prod",
  "revoked_node_id": "dir:org-c:prod",
  "reason": "contract_terminated",
  "issued_at": "2026-07-01T12:00:00Z",
  "expires_at": "2026-08-01T12:00:00Z",
  "issuer": "dir:org-a:prod",
  "signature": {
    "key_id": "org-a-node-signing-2026-q3",
    "sig": "..."
  }
}
```

A receiving node treats revocation notices according to local policy. For example, it may trust
revocations only from directly contracted partners or from a charter key.

## 9. Real-Life Flow: Org C Joins Org A and Org B

Assume:

- Org A and Org B already know and accept each other.
- Org A has node `dir:org-a:prod`.
- Org B has node `dir:org-b:prod`.
- Org C wants to join with node `dir:org-c:prod`.
- Org C is configured with Org A and Org B as seed peers.

### 9.1 Starting State

Org A and Org B each have local membership tables:

```text
Org A local members: dir:org-b:prod active
Org B local members: dir:org-a:prod active
```

There is no global roster file containing A and B.

### 9.2 Org C Publishes Its Manifest

Org C publishes:

```text
https://dir.org-c.example/.well-known/agent-directory.json
```

Org C's manifest contains its endpoint, key, federation ID, protocol version, and admission
evidence.

### 9.3 Org C Introduces Itself

Org C calls:

```text
POST https://dir.org-a.example/federation/v1/members/introduce
POST https://dir.org-b.example/federation/v1/members/introduce
```

Org A and Org B independently:

1. verify Org C's signed introduction;
2. fetch Org C's manifest directly from `https://dir.org-c.example`;
3. verify Org C's manifest signature and domain proof;
4. check local admission policy;
5. call Org C `/protocol`;
6. decide whether to accept, reject, or quarantine Org C.

Possible outcomes:

```jsonc
{ "accepted": true, "accepted_until": "2026-07-08T10:00:00Z" }
```

```jsonc
{ "accepted": false, "reason": "policy_denied" }
```

Org A accepting Org C does not force Org B to accept Org C.

### 9.4 Org C Learns More Peers

If Org A accepts Org C, Org C can call:

```text
GET https://dir.org-a.example/federation/v1/members
```

Org A may disclose Org B's manifest URL to Org C:

```jsonc
{
  "members": [
    {
      "node_id": "dir:org-b:prod",
      "manifest_url": "https://dir.org-b.example/.well-known/agent-directory.json"
    }
  ]
}
```

Org C still must fetch Org B's manifest directly and introduce itself to Org B. Org A is only an
introducer.

### 9.5 Org A Queries After Accepting Org C

When a requester in Org A searches:

```text
"find an agent that reconciles supplier invoices"
```

Org A:

1. authenticates the local requester;
2. selects eligible peers from its local membership table;
3. includes Org C only if Org C is accepted and healthy;
4. sends signed `POST /query` to Org B and Org C;
5. receives signed result cards;
6. merges results with provenance and coverage.

Coverage is local-view coverage:

```jsonc
{
  "membership_view": "local",
  "known_peers": 2,
  "eligible_peers": 2,
  "queried_peers": 2,
  "responded_peers": 2,
  "timed_out_peers": []
}
```

This does not claim "the entire federation was searched." It claims "this node searched the
eligible peers in its current local membership view."

### 9.6 Fetching a Record from Org C

If Org A selects a result owned by Org C:

```text
GET https://dir.org-c.example/federation/v1/records/agent:org-c:invoice-agent?format=oasf
```

Org C re-checks authorization and returns the signed projection emitted by its local ADR-003
directory.

### 9.7 Org C Rotates Keys

Org C updates its manifest revision and publishes the new key. Existing peers detect the change
through direct manifest refresh. Each peer applies its own key-continuity policy:

- accept if the old key signs the new key;
- accept if admission evidence authorizes the new key;
- quarantine if key continuity cannot be proven;
- reject if local policy denies the rotation.

### 9.8 Org C Becomes Unhealthy

If Org C times out, peers keep Org C in their membership table but mark it `cooldown`. Query
coverage reports Org C as skipped or timed out. Health is local and does not require global
consensus.

### 9.9 Org C Is Removed

There is no central removal event. Removal happens through local policy:

- Org A may reject Org C after contract termination.
- Org B may still accept Org C if its own contract remains valid.
- If a trusted charter/admission credential expires, all nodes that rely on that credential will
  reject Org C on refresh.
- If a signed revocation notice is trusted by local policy, the node marks Org C `revoked`.

This is the consequence of strict no-central-membership: membership is not globally atomic. The
network converges by peer refresh, credential expiry, and local policy.

## 10. Federation APIs

All federation APIs are HTTPS. Paths below are relative to the manifest `endpoint`.

| API | Purpose |
|---|---|
| `GET /protocol` | Returns protocol version, supported auth methods, limits, and current node metadata. |
| `GET /capability-summary` | Returns optional coarse metadata used by peers to decide whether to query this node. |
| `POST /members/introduce` | Introduce this node's signed manifest to a peer. |
| `GET /members?since=...` | Return locally known peer manifest references the requester is allowed to see. |
| `GET /revocations?since=...` | Return trusted revocation notices known to this node. |
| `POST /query` | Peer-to-peer discovery request. Returns signed lightweight result cards. |
| `GET /records/{record_id}` | Fetches a full record/projection from the owning node. |
| `GET /health` | Operational health probe. Does not replace authenticated query/fetch checks. |

## 11. Request Authentication

Use at least one of:

1. **mTLS** with certificate identities mapped to accepted peer manifests.
2. **Signed HTTP requests** using the node key advertised in the peer's current manifest.

Signed requests are useful when mTLS federation across organizations is operationally hard.
mTLS is useful where enterprise PKI and network policy already exist.

### 11.1 Signed Request Envelope

Every signed peer request includes:

```jsonc
{
  "federation_id": "supplier-network-prod",
  "request_id": "018ff6f2-...",
  "source_node_id": "dir:org-a:prod",
  "target_node_id": "dir:org-c:prod",
  "method": "POST",
  "path": "/federation/v1/query",
  "timestamp": "2026-07-01T10:00:00Z",
  "nonce": "base64...",
  "body_sha256": "sha256:...",
  "source_manifest_revision": 12,
  "signature": {
    "key_id": "org-a-node-signing-2026-q3",
    "alg": "EdDSA",
    "sig": "..."
  }
}
```

The receiving node validates:

- source node is accepted in the local membership table;
- source manifest key is current or allowed during rotation;
- signature covers method, path, timestamp, nonce, and body hash;
- timestamp is inside skew window;
- nonce was not replayed;
- target node matches self;
- source is allowed by local disclosure/rate policy.

## 12. Query Protocol

Federation standardizes the query envelope. It does not standardize how a node searches its
local catalogue.

### 12.1 Query Request

```jsonc
{
  "query_id": "q-123",
  "query": {
    "text": "agent that reconciles supplier invoices",
    "filters": {
      "domains": ["finance"],
      "skills": ["invoice.reconcile"],
      "record_type": "oasf-agent"
    }
  },
  "requested_fields": ["record_id", "name", "summary", "owner_org", "domains", "skills"],
  "limit": 20,
  "timeout_ms": 2000,
  "disclosure_context": {
    "requester_org": "org-a",
    "purpose": "procurement-workflow"
  }
}
```

`query.text` is optional if filters are sufficient. A node may implement text search with vector
search, lexical search, SQL filters, a document index, or any local mechanism defined in ADR-003.

### 12.2 Query Response

```jsonc
{
  "query_id": "q-123",
  "source_node_id": "dir:org-c:prod",
  "results": [
    {
      "record_id": "agent:org-c:invoice-agent",
      "record_type": "oasf-agent",
      "name": "Invoice Reconciliation Agent",
      "summary": "Reconciles supplier invoices against purchase orders.",
      "owner_org": "org-c",
      "domains": ["finance"],
      "skills": ["invoice.reconcile"],
      "revision": 17,
      "fetch_url": "https://dir.org-c.example/federation/v1/records/agent:org-c:invoice-agent",
      "provenance": {
        "node_id": "dir:org-c:prod",
        "content_hash": "sha256:..."
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

The owning node signs result cards so downstream consumers can retain provenance even after the
querying node merges results from many peers.

## 13. Fetch Protocol

Query returns lightweight result cards. Full records are fetched explicitly from the owning node.

```text
GET /federation/v1/records/{record_id}?format=oasf
GET /federation/v1/records/{record_id}?format=a2a-card
GET /federation/v1/records/{record_id}?format=did-ref
```

The valid `format` values and projection rules are owned by ADR-003.

The owning node MUST re-check authorization on fetch. Permission to see a lightweight result does
not imply permission to fetch the full record or a sensitive projection.

## 14. Capability Summary

A node may publish a coarse capability summary to help peers decide whether querying it is worth
the latency. This is an optimization, not the source of truth.

```jsonc
{
  "node_id": "dir:org-c:prod",
  "summary_version": 5,
  "record_types": ["oasf-agent"],
  "domains": ["finance", "procurement"],
  "skills_top": ["invoice.reconcile", "supplier.lookup"],
  "coverage_text": "Supplier, invoice, and procurement agents.",
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

Federation does not require peers to use the same search engine or embedding model.

## 15. Fan-Out and Coverage

The querying node controls fan-out:

1. select eligible peers from its local membership table;
2. remove rejected, revoked, stale, or unhealthy peers;
3. optionally use capability summaries to prioritize likely peers;
4. query selected peers in parallel with a deadline;
5. report local-view coverage honestly.

Coverage metadata should include:

```jsonc
{
  "membership_view": "local",
  "known_peers": 14,
  "eligible_peers": 8,
  "queried_peers": 6,
  "responded_peers": 5,
  "timed_out_peers": ["dir:org-d:prod"],
  "skipped_peers": [
    { "node_id": "dir:org-e:prod", "reason": "cooldown" },
    { "node_id": "dir:org-f:prod", "reason": "policy_denied" }
  ],
  "deadline_hit": true
}
```

In a hubless design, coverage is not a global completeness claim. It is a truthful statement
about the querying node's current local membership view.

## 16. Liveness and Health

Membership validity and runtime health are separate.

| State | Meaning | Behavior |
|---|---|---|
| `active` | Locally admitted and recently healthy. | Eligible for query/fetch. |
| `cooldown` | Recent timeouts, errors, or rate limits. | Skip or deprioritize until backoff expires. |
| `stale_manifest` | Manifest expired or failed validation. | Do not query until refreshed. |
| `rejected` | Local admission policy denied the peer. | Do not query. |
| `revoked` | Local policy or trusted revocation denies the peer. | Do not query; reject inbound requests. |

Health is determined by:

- successful query/fetch/protocol calls;
- direct manifest refresh success;
- `GET /health` as a weak signal;
- operator override.

## 17. Why SWIM Is Harder for Enterprise Networks

SWIM-style protocols solve membership and failure detection for dynamic clusters. They are good
when nodes are numerous, churn frequently, and can participate in a gossip plane.

They are harder in enterprise and cross-org directory federation because:

- **Network ports and protocols.** SWIM/memberlist deployments commonly expect direct peer-to-peer
  connectivity and often use UDP or separate gossip ports. Enterprise firewalls, NAT, proxies,
  and partner network boundaries usually prefer outbound HTTPS and explicitly approved inbound
  endpoints.
- **Security review.** Security teams understand HTTPS APIs, mTLS, signed requests, allowlists,
  and audit logs. Gossip protocols introduce background peer traffic, indirect probes, and
  message dissemination patterns that are harder to inspect and explain.
- **Admission vs liveness coupling.** SWIM tells you who appears alive. It does not by itself
  answer whether an organization is contractually admitted, what it may see, or which records it
  may query. You still need signed manifests, admission evidence, and disclosure policy.
- **Cross-org trust.** SWIM is cluster membership machinery. A supplier/partner federation needs
  per-peer trust, domain proof, contract state, revocation, and audit. Those are application-layer
  concerns outside SWIM.
- **Operational blast radius.** Misconfigured gossip can spread bad peer state quickly. Hubless
  signed-manifest exchange converges more slowly, but each node keeps local control and can
  quarantine peers independently.
- **Churn profile mismatch.** Directory instances should change slowly compared with compute
  workers. Manifest TTLs, introductions, active probes, and local cooldown are usually enough.

Therefore SWIM should not be the default for production enterprise federation. It can be
considered later as an optional liveness accelerator inside one controlled network, but not as
the cross-org trust and discovery foundation.

## 18. Alternatives

### 18.1 Keep Hubless Signed-Manifest Exchange

This is the chosen option.

Pros:

- no central membership record;
- works over ordinary HTTPS;
- every node owns its admission/disclosure decisions;
- enterprise-friendly audit and security model;
- seed peers are replaceable introducers, not authorities;
- no DHT or gossip plane required.

Cons:

- membership convergence is eventual;
- no global completeness guarantee;
- revocation is local-policy based unless a trusted charter credential is used;
- each node must implement membership exchange logic.

### 18.2 Use SWIM / Memberlist

Pros:

- fast decentralized liveness detection;
- mature implementations exist;
- useful for high-churn clusters.

Cons:

- harder enterprise firewall/NAT posture;
- harder cross-org security review;
- still requires signed manifests and admission policy;
- not a semantic discovery/query protocol;
- likely unnecessary for low-churn directory nodes.

### 18.3 Use Central Roster / Registry

Rejected for this project because it creates a central membership record, even if it is not in
the runtime query path.

Pros:

- simplest operational model;
- clean global membership and revocation;
- strong coverage denominator.

Cons:

- violates strict no-central-record requirement;
- creates governance/control concentration;
- makes federation availability dependent on external publication flow unless carefully cached.

### 18.4 Use DHT / libp2p

Rejected for production v1.

Pros:

- decentralized lookup;
- useful in open networks.

Cons:

- poor enterprise firewall/proxy fit;
- harder audit and traffic inspection;
- does not solve admission, disclosure, semantic query, or record provenance;
- unnecessary for governed BU/org directories.

## 19. Security and Abuse Controls

Nodes MUST implement:

- manifest signature verification;
- peer request authentication;
- local admission policy before accepting a peer;
- authorization before query and fetch;
- per-peer rate limits;
- request size limits;
- response result limits;
- replay protection for signed requests;
- SSRF controls for manifest refresh;
- private/link-local IP blocking unless explicitly allowed by enterprise network policy;
- audit logs for inbound and outbound membership/query/fetch;
- local revocation and quarantine controls.

## 20. Audit

Each node keeps an append-only audit log of:

- manifests fetched and validated;
- peer introductions accepted/rejected;
- membership entries learned from peers;
- revocation notices received/applied;
- inbound peer queries;
- outbound peer queries;
- result counts and coverage;
- fetch requests and projection formats;
- authorization decisions;
- rate-limit and rejection events;
- key rotations.

Logs should include `request_id`, `query_id`, source node, target node, manifest revision, local
membership decision, and decision reason.

## 21. Enterprise Production Shape

Recommended production shape:

```text
Bootstrap:
  configure 2-3 seed manifest URLs
  configure trusted admission issuers/domain rules

Node publication:
  well-known signed manifest
  short manifest TTL
  stable HTTPS endpoint
  published limits and protocol versions

Membership:
  /members/introduce
  /members?since=...
  direct manifest refresh
  local membership table
  local admission/disclosure policy

Runtime:
  signed HTTP requests and/or mTLS
  direct node-to-node HTTPS query/fetch
  local visibility enforcement
  signed result cards
  explicit fetch for full records
  local-view coverage reporting

Operations:
  passive health + protocol probes
  cooldown/backoff
  audit logs
  per-peer quotas
  quarantine/revocation controls
```

This is enterprise-applicable because it avoids central membership infrastructure while still
using controls security teams understand: HTTPS, signed manifests, mTLS/signed requests,
allowlists, audit, local revocation, and explicit trust policy.

## 22. Phasing

### Phase 1 - Hubless Federation MVP

- Well-known signed manifests.
- Static seed peer config.
- `POST /members/introduce`.
- `GET /members?since=...`.
- Direct manifest refresh.
- Signed HTTP request authentication.
- `GET /protocol`.
- `POST /query`.
- `GET /records/{record_id}`.
- Basic local disclosure checks.
- Local-view coverage report.
- Audit logs.

### Phase 2 - Enterprise Hardening

- Manifest key rotation.
- mTLS option.
- Per-peer quotas and rate limits.
- Health states and cooldown.
- Revocation notices.
- Quarantine workflow.
- Negative tests for replay, SSRF, stale manifests, revoked peers, and policy-denied peers.

### Phase 3 - Discovery Optimization

- Capability summaries.
- Peer prioritization.
- Query fan-out budgets.
- Partial-result UX.
- Better local-view coverage reporting.

### Phase 4 - Optional Advanced Liveness

Only if measured production needs justify it:

- SWIM/memberlist inside one controlled network for liveness only;
- richer peer-state gossip;
- Merkle membership reconciliation;
- DHT/open-network discovery in a separate ADR.

## 23. Open Questions

1. **Admission evidence.** Is domain proof enough for internal BUs, and what credential is needed
   for cross-org partners?
2. **Seed peer policy.** How many seed peers should each node configure, and who operates them?
3. **Disclosure model.** Which peer metadata may `/members` return to a newly admitted node?
4. **Revocation trust.** Which revocation issuers does a node trust automatically?
5. **Key rotation.** What proof is required when a node rotates its signing key?
6. **Coverage UX.** How should users see local-view results and unreachable peers?
7. **Sensitive query handling.** Which queries may not be sent to all eligible known peers?
8. **mTLS vs signed HTTP.** Which is mandatory for internal BU federation and which for cross-org
   federation?
9. **Audit retention.** How long do nodes keep query intent and peer access logs?
