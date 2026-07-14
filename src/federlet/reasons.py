"""Shared machine-readable outcome reasons for structured reports.

Every fan-out report federlet produces — `SeedBootstrapReport`,
`DiscoveryRefreshReport`, and `OperationFanOutReport` — draws its failure
reasons from one vocabulary so a caller can uniformly log and aggregate
accepted/rejected/skipped/failed outcomes across bootstrap, discovery, and
operations. Flow-specific reasons (e.g. a malformed *manifest* vs a malformed
*response*, or discovery skip reasons like `per_peer_cap`) stay with their
call site; this module owns the transport/network reasons they all share.
"""

from __future__ import annotations

import asyncio

import httpx

from .net import SSRFError

# Shared transport / network reasons.
SSRF_REJECTED = "ssrf_rejected"
TIMEOUT = "timeout"
HTTP_ERROR = "http_error"
TRANSPORT_ERROR = "transport_error"


def transport_failure_reason(exc: Exception) -> str | None:
    """Map a common transport/network exception to a shared reason, or None.

    Callers classify their own domain exceptions first (bad manifest, bad
    response signature, malformed body) and delegate the shared network cases
    here. Returns None when `exc` is not a recognized transport error, so the
    caller can fall back to its own default.
    """
    match exc:
        case SSRFError():
            return SSRF_REJECTED
        case httpx.TimeoutException() | asyncio.TimeoutError():
            return TIMEOUT
        case httpx.HTTPStatusError():
            return HTTP_ERROR
        case httpx.TransportError():
            return TRANSPORT_ERROR
        case httpx.HTTPError():
            return HTTP_ERROR
        case _:
            return None
