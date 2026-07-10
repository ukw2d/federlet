"""One-shot peer health probe classification."""

from __future__ import annotations

from dataclasses import dataclass

from .client import FederationClient
from .membership import PeerState
from .models import HealthResponse, Manifest, ProtocolResponse

HEALTHY_STATUSES = {"ok", "healthy", "pass"}


@dataclass(frozen=True)
class PeerHealthProbeResult:
    healthy: bool
    reason: str = "ok"
    suggested_state: PeerState = PeerState.ACTIVE
    protocol: ProtocolResponse | None = None
    health: HealthResponse | None = None
    error: str | None = None


async def probe_peer_health(
    client: FederationClient,
    peer: Manifest,
) -> PeerHealthProbeResult:
    """Call one peer's protocol and health probes once and classify the result."""
    try:
        protocol = await client.get_protocol(peer)
    except Exception as exc:
        return PeerHealthProbeResult(
            False,
            "protocol_probe_failed",
            PeerState.COOLDOWN,
            error=str(exc) or exc.__class__.__name__,
        )

    try:
        health = await client.get_health(peer)
    except Exception as exc:
        return PeerHealthProbeResult(
            False,
            "health_probe_failed",
            PeerState.COOLDOWN,
            protocol=protocol,
            error=str(exc) or exc.__class__.__name__,
        )

    if health.status.lower() not in HEALTHY_STATUSES:
        return PeerHealthProbeResult(
            False,
            "unhealthy",
            PeerState.COOLDOWN,
            protocol=protocol,
            health=health,
        )

    return PeerHealthProbeResult(
        True,
        protocol=protocol,
        health=health,
    )
