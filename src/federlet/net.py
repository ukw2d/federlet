"""Shared host/IP classification for the SSRF guard and admission policy.

Kept in one place so a future tightening of "what counts as a non-public
address" can't be applied to only one of the two call sites that need it.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class SSRFError(ValueError):
    """Raised when a URL resolves to a disallowed address."""


def is_disallowed_ip(ip: IPAddress) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _assert_public_host(url: str, allow_private: bool = False) -> None:
    host = urlparse(url).hostname
    if not host:
        raise SSRFError(f"no host in url: {url}")
    if allow_private:
        return
    for _, _, _, _, sockaddr in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(sockaddr[0])
        if is_disallowed_ip(ip):
            raise SSRFError(f"{host} resolves to non-public address {ip}")
