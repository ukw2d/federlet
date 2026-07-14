"""Generic operation fan-out: call one OperationRequest on many peers.

federlet standardizes only the mechanics — sign, send, verify, and collect a
structured per-peer success/failure report concurrently. It knows nothing about
the operation's name, payload schema, coverage, ranking, or how results merge;
those stay host-owned. Each target is a peer paired with the host-resolved
operations URL (federlet does not resolve endpoint paths).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from json import JSONDecodeError

from pydantic import ValidationError

from .client import FederationClient, ResponseSignatureError
from .models import Manifest
from .operations import OperationRequest, OperationResponse
from .reasons import transport_failure_reason

# A peer manifest paired with its host-resolved operations endpoint URL.
OperationTarget = tuple[Manifest, str]


@dataclass(frozen=True)
class OperationOutcome:
    node_id: str
    operations_url: str
    reason: str = "ok"
    response: OperationResponse | None = None
    source_node_id: str | None = None
    manifest_url: str | None = None


@dataclass(frozen=True)
class OperationFanOutReport:
    succeeded: list[OperationOutcome]
    failed: list[OperationOutcome]


async def fan_out_operation(
    client: FederationClient,
    request: OperationRequest,
    targets: Iterable[OperationTarget],
    *,
    timeout: float | None = None,
) -> OperationFanOutReport:
    """Send one operation request to every target concurrently and collect results.

    `targets` pairs each peer manifest with its host-resolved operations URL.
    Calls run concurrently; `timeout`, when set, bounds each individual call.
    Never raises for a peer failure — every target lands in `succeeded` or
    `failed` with a machine-readable reason.
    """
    target_list = list(targets)
    outcomes = await asyncio.gather(
        *(_call_one(client, request, peer, url, timeout) for peer, url in target_list)
    )
    succeeded = [o for o in outcomes if o.reason == "ok"]
    failed = [o for o in outcomes if o.reason != "ok"]
    return OperationFanOutReport(succeeded=succeeded, failed=failed)


async def _call_one(
    client: FederationClient,
    request: OperationRequest,
    peer: Manifest,
    operations_url: str,
    timeout: float | None,
) -> OperationOutcome:
    try:
        coro = client.send_operation(peer, request, operations_url=operations_url)
        response = await (asyncio.wait_for(coro, timeout) if timeout else coro)
    except Exception as exc:
        return _outcome(peer, operations_url, _failure_reason(exc))
    return _outcome(peer, operations_url, "ok", response)


def _outcome(
    peer: Manifest,
    operations_url: str,
    reason: str,
    response: OperationResponse | None = None,
) -> OperationOutcome:
    return OperationOutcome(
        node_id=peer.node_id,
        operations_url=operations_url,
        reason=reason,
        response=response,
        source_node_id=peer.node_id,
        manifest_url=peer.manifest_url,
    )


def _failure_reason(exc: Exception) -> str:
    match exc:
        case ResponseSignatureError():
            return "bad_signature"
        case ValidationError() | JSONDecodeError():
            return "malformed_response"
    return transport_failure_reason(exc) or exc.__class__.__name__
