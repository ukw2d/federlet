# Changelog

All notable changes to federlet are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses SemVer-style version numbers. While federlet is pre-1.0,
minor releases may include intentional API changes; patch releases should remain
backwards-compatible bugfixes and documentation-only updates.

## [Unreleased]

## [0.6.0] - 2026-07-15

### Added

- Added async `ManifestStore` as a write-through durability port for admitted
  peer manifests. `FederationNode` now accepts `manifest_store=...`, hydrates an
  empty `peer_manifests` cache via `await hydrate()` / `async with`, and
  persists admitted, discovered, and refreshed manifests through the store.
- Added durable manifest eviction on refresh reject and trusted node-level
  revocation so rejected/revoked peers do not survive restart through a stale
  persisted manifest.
- Added a per-node lifecycle lock around membership/manifest mutations to avoid
  revoke/admit interleavings that could resurrect a revoked manifest.

### Changed

- **Breaking:** `MembershipStore` is now fully async. Implementors must expose
  `async get`, `async upsert`, `async values`, and `async delete`; federlet
  callers now await membership reads/writes.
- **Breaking:** `RateLimiter.allow` is now async so Redis/Valkey-backed
  distributed limiters do not block the event loop.
- `eligible_peers`, `apply_revocation_notice`, and `FederationNode.select_peers`
  are async because they touch async membership storage.
- `verify_known_inbound` remains a lockless in-memory `peer_manifests` read and
  never calls the durable manifest store on the inbound request path.

### Migration notes

- Update durable membership adapters to async methods and add `delete(node_id)`.
- Update rate limiter adapters to `async allow(...)` and await calls to
  `TokenBucketRateLimiter.allow(...)`.
- If using `FederationNode` with durable manifests, pass
  `manifest_store=adapter` and either use `async with FederationNode(...)` or
  call `await node.hydrate()` before serving inbound requests.
- Plakard x39 should pin `federlet>=0.6` and implement one async cashews-backed
  adapter satisfying both `MembershipStore` and `ManifestStore`.

## [0.4.0] - 2026-07-13

### Changed

- Replaced the query/result API with generic operation envelopes:
  `OperationRequest`, `OperationResponse`, `OperationItem`, and
  `PayloadProvenance`.
- Replaced `sign_query_response` with `sign_operation_response`.
- Replaced result-item signing helpers with `sign_operation_item`,
  `sign_operation_payload`, and `verify_operation_item`.
- Replaced `Manifest.capability_summary_url` with opaque
  `Manifest.extensions` for host protocol metadata.
- Renamed manifest limits from query/result terminology to operation
  terminology: `max_operation_rps_per_peer`, `max_operation_timeout_ms`, and
  `max_operation_items`.
- Renamed audit `query_id` metadata to `operation_id`.
- Updated ADR-005, README, package metadata, and tests to position federlet as a
  host-protocol-agnostic federation core.

### Migration notes

- Replace imports and constructors:
  - `QueryRequest` → `OperationRequest`
  - `QueryResponse` → `OperationResponse`
  - `ResultRef` / `FederatedResult` → `OperationItem`
  - `ResultProvenance` → `PayloadProvenance`
  - `sign_query_response` → `sign_operation_response`
  - `sign_result` → `sign_operation_item` or `sign_operation_payload`
  - `verify_result` → `verify_operation_item`
- Move query criteria, requested fields, coverage, ranking, fetch references,
  and other host semantics into `OperationRequest.payload`,
  `OperationRequest.metadata`, `OperationResponse.payload`,
  `OperationResponse.metadata`, or `OperationItem.payload`.
- Move host capability or profile discovery URLs into `Manifest.extensions`.
- Remove use of `CapabilitySummary` and `sign_capability_summary` from federlet;
  hosts own those models if they need them.

## [0.3.0] - 2026-07-13

### Changed

- Reframed federlet as a domain-neutral federation library. Host products now
  own their protocol identifier, manifest publication path, record vocabulary,
  query semantics, result attributes, and capability facets.
- Replaced `ResultCard` with `ResultRef`. The result reference core now contains
  `record_id`, `fetch_url`, optional `revision`, host-owned `attributes`,
  provenance, and signature.
- Renamed `sign_result_card` to `sign_result` and `verify_result_card` to
  `verify_result`.
- Replaced typed `CapabilitySummary.domains` and
  `CapabilitySummary.skills_top` fields with host-owned
  `CapabilitySummary.facets`.
- Made `build_signed_manifest(..., protocol_versions=...)` explicit; federlet no
  longer provides a default host protocol identifier.
- Added optional `Manifest.manifest_url` and removed path guessing from
  `FederationNode.admit_peer`. Hosts must pass `manifest_url` explicitly or
  advertise it in the peer manifest.
- Restructured ADR-005 into a universal federation core with a Plakard profile
  appendix for product-specific vocabulary.

### Migration notes

- Move previous `ResultCard.record_type`, `name`, `summary`, `owner_org`,
  `domains`, and `skills` data under `ResultRef.attributes` using the host
  schema.
- Replace imports and calls:
  - `ResultCard` → `ResultRef`
  - `sign_result_card` → `sign_result`
  - `verify_result_card` → `verify_result`
- Move previous capability summary categories into `facets`, for example
  `{"domains": [...], "skills": [...]}` in a Plakard host profile.
- Pass `protocol_versions` explicitly when building manifests.
- Pass `manifest_url` explicitly to `build_signed_manifest` or set
  `Manifest.manifest_url`; do not rely on a derived well-known path.

### Removed

- Removed the `agent-directory-federation/1` default protocol version from the
  library.
- Removed hardcoded `/.well-known/agent-directory.json` manifest URL derivation
  from the library.
- Removed compatibility aliases for the former result-card API.

## [0.2.0] - 2026-07-10

### Added

- Release documentation for changelog maintenance, SemVer expectations, and
  `vX.Y.Z` source tags.
- User-facing guidance for choosing between the `FederationNode` facade,
  `federlet.prelude`, and `federlet.lowlevel`.
- Typed signed response helper facades for introduction, membership,
  revocation, and query responses.
- Stateful facade helpers for common host workflows, including inbound
  verification, publication, bootstrap, discovery, refresh, and peer selection.

### Changed

- Discovery refresh internals now collect outcomes through a private accumulator
  instead of threading separate accepted/rejected/skipped/failed lists.

## [0.1.0] - 2026-07-10

### Added

- Async framework-neutral federation protocol library for peer directory
  services.
- Signed node manifests with Ed25519/JWK helpers and RFC 8785 canonical JSON
  signing.
- Signed HTTP request envelopes with freshness, target, method, path, body-hash,
  signature, and replay checks.
- Local manifest admission policy, admission evidence callback support,
  endpoint-domain checks, and SSRF protection for fetched manifests and admitted
  endpoints.
- Membership table helpers, peer disclosure filtering, revocation application,
  manifest refresh, key-continuity decisions, health probing, and bounded peer
  discovery.
- Async `httpx` client helpers for manifest fetch, introduction, members,
  revocations, capability summaries, protocol, and health endpoints.
- Seed-bootstrap helper, capability-summary signing helper, signed manifest
  builder, typed response signing helpers, query/result-reference wire models,
  and an optional stateful `FederationNode` facade.
- Structural protocols for host-owned nonce caches, rate limiters, and
  membership stores.
- Typed package metadata via `py.typed`.

[Unreleased]: https://github.com/ukw2d/federlet/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/ukw2d/federlet/compare/v0.4.0...v0.6.0
[0.4.0]: https://github.com/ukw2d/federlet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ukw2d/federlet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ukw2d/federlet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ukw2d/federlet/releases/tag/v0.1.0
