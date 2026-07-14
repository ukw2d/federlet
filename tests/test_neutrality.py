"""Domain-neutrality conformance guard.

federlet is a domain-agnostic federation core. It must never learn host-specific
path knowledge (e.g. an ``agent-directory.json`` well-known path), host operation
names (e.g. ``directory.search``), a downstream product identity (e.g. Plakard),
or enterprise auth semantics (e.g. OIDC/JWKS token validation). Hosts own all of
that and plug it in through federlet's documented hooks.

This test scans the shipped package source for a denylist of tokens whose
presence signals such a regression. It is intentionally simple and data-driven:
add a token to ``FORBIDDEN_TOKENS`` to lock out a new leak.
"""

from __future__ import annotations

from pathlib import Path

import federlet

# Case-insensitive substrings that must never appear in shipped federlet source.
# Each maps to a short reason shown when the guard trips. Keep tokens specific:
# generic words that legitimately appear in the protocol core (e.g. "issuer" on
# RevocationNotice, or the "well_known_url" helper name) must not be denied.
FORBIDDEN_TOKENS: dict[str, str] = {
    "plakard": "downstream product identity — federlet stays product-neutral",
    "agent-directory": "host path knowledge — hosts resolve their own URLs",
    "agent_directory": "host path knowledge — hosts resolve their own URLs",
    "directory.search": "host operation name — federlet does not know operations",
    "directory_search": "host operation name — federlet does not know operations",
    ".well-known": "hardcoded well-known path — callers supply paths to well_known_url",
    "oidc": "enterprise auth semantics — expose hooks, do not implement OIDC",
    "openid": "enterprise auth semantics — expose hooks, do not implement OIDC",
}

PACKAGE_ROOT = Path(federlet.__file__).parent


def _package_sources() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def test_shipped_sources_exist():
    # Guard against the scan silently passing on an empty file set.
    assert _package_sources(), "no federlet source files found to scan"


def test_no_host_specific_tokens_in_source():
    violations: list[str] = []
    for path in _package_sources():
        text = path.read_text(encoding="utf-8").lower()
        for token, reason in FORBIDDEN_TOKENS.items():
            if token in text:
                rel = path.relative_to(PACKAGE_ROOT.parent)
                violations.append(f"{rel}: '{token}' — {reason}")
    assert not violations, "domain-neutrality violations:\n" + "\n".join(violations)
