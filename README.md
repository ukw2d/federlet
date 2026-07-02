# pimx — Peer Introduction and Manifest Exchange

A hubless HTTPS federation protocol core for directory nodes (ADR-005).

pimx is a **library**: it owns the protocol *semantics* — signing and verifying
manifests and request envelopes, freshness/skew checks, replay *logic*, and
admission *policy*. It deliberately does **not** own infrastructure. The cache
that backs replay protection, the trust material that backs admission evidence,
and the HTTP server that exposes your node are all supplied by the host app
through narrow injection points. pimx is fully `async`.

## Install

```bash
pip install pimx                # core only — no cache backend pulled in
pip install pimx[cashews]       # + cashews, the recommended replay-cache backend
```

pimx never imports a cache backend. `verify_signed_request` only calls
`set(..., exist=False)` on a `NonceCache` you inject — a cashews `Cache`
satisfies that shape directly, but so does any compatible object.

## Wiring pimx into your app

### 1. Configure the replay cache (host-owned config)

pimx reads no environment variables. Configuration lives in *your* app. A
`pydantic-settings` model with a prefix is the idiomatic way to turn `.env` /
environment into a configured cache:

```python
# app/settings.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PIMX_", env_file=".env")
    cache_url: str = "mem://"          # PIMX_CACHE_URL=redis://… (or valkey) in prod

settings = Settings()
```

```python
# app/deps.py
from cashews import Cache

cache = Cache()
cache.setup(settings.cache_url)        # cashews parses the DSN; mem:// / redis:// / …
```

### 2. Verify inbound signed requests

Inject that `cache` — pimx claims the nonce (TTL == skew window) only after the
signature verifies, so unauthenticated traffic can't burn nonces:

```python
from pimx import verify_signed_request, SignedRequest, find_jwk

env = SignedRequest.model_validate_json(request.headers["X-PIMX-Signature"])
jwk = find_jwk(peer_manifest.public_keys, env.signature.key_id)

ok, reason = await verify_signed_request(
    env, jwk, self_node_id=my_node_id, body=raw_body, cache=cache,
)
if not ok:
    raise HTTPException(401, reason)
```

### 3. Admit peer manifests (host-owned trust)

Admission evidence (SPIFFE, partner credentials, charter keys) is host trust
material no library can ship, so it's an injected async callback. A minimal
built-in `domain_evidence_verifier` is provided for `domain_proof` evidence:

```python
from pimx import admit_manifest, AdmissionPolicy, domain_evidence_verifier

policy = AdmissionPolicy(
    federation_id="supplier-network-prod",
    protocol_versions={"agent-directory-federation/1"},
    evidence_verifier=domain_evidence_verifier,   # or your own async verifier
)
decision = await admit_manifest(peer_manifest, policy)
```

### 4. Make outbound calls

```python
from pimx import FederationClient, Query

async with FederationClient(
    node_id=my_node_id, federation_id=fed_id, key=my_key, key_id=my_key_id,
) as client:
    results, coverage = await client.federated_query(peers, Query(query_id="q1", query={...}))
```

### 5. Expose your node (host-owned server)

pimx does not ship a server. Wire its verifiers/signers into your async
framework (FastAPI, etc.); `tests/harness.py` shows the same wiring against the
stdlib server for integration tests.

## Extension points

| Concern            | pimx provides            | Host provides                          |
| ------------------ | ------------------------ | -------------------------------------- |
| Replay storage     | `NonceCache` Protocol    | a cashews `Cache` (or compatible)      |
| Admission evidence | `EvidenceVerifier` port  | async verifier + trust material        |
| HTTP server        | signers/verifiers        | the ASGI/HTTP app                      |
| Configuration      | —                        | `pydantic-settings` (or equivalent)    |
