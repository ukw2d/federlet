# Changelog

All notable changes to federlet are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses SemVer-style version numbers. While federlet is pre-1.0,
minor releases may include intentional API changes; patch releases should remain
backwards-compatible bugfixes and documentation-only updates.

## [Unreleased]

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
  builder, typed response signing helpers, query/result-reference wire models, and an
  optional stateful `FederationNode` facade.
- Structural protocols for host-owned nonce caches, rate limiters, and
  membership stores.
- Typed package metadata via `py.typed`.

[Unreleased]: https://github.com/ukw2d/federlet/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ukw2d/federlet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ukw2d/federlet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ukw2d/federlet/releases/tag/v0.1.0
