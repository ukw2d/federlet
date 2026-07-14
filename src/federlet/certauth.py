"""Generic certificate-identity authentication primitive (mTLS).

An alternative/complement to signed_http for deployments where TLS client
certificates already establish peer identity. federlet provides only the
mechanical primitive: normalize a presented certificate identity and match it
against a host-supplied expected identity, yielding a `CertVerifiedPeer` bound
to a node_id the host chooses.

federlet owns no policy here. It ships no CA bundle, resolves no trust roots,
and never maps a certificate to a node itself. The host's TLS terminator
supplies the presented identity (proxy header or TLS socket), the host resolves
which identity it expects for a node (its cert-to-peer policy), and the host
supplies the node_id. See ADR-005 sections 4.1 and 7.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from hmac import compare_digest


def certificate_thumbprint(cert_der: bytes) -> str:
    """SHA-256 thumbprint of a DER-encoded certificate (RFC 8705 `x5t#S256`).

    Objective and parse-free: this is a hash of the presented bytes, not a
    trust decision. Hosts typically read the DER from their TLS layer.
    """
    return "sha256:" + hashlib.sha256(cert_der).hexdigest()


@dataclass(frozen=True)
class CertificateIdentity:
    """Normalized identity extracted from a peer's TLS certificate.

    Every field is host-supplied. When used as the *expected* identity, non-empty
    fields act as constraints the presented identity must satisfy: `spki_sha256`
    and `subject_dn` by equality, `sans` by subset (every expected SAN must be
    present). An entirely empty expected identity matches nothing (fail closed).
    """

    subject_dn: str | None = None
    sans: tuple[str, ...] = ()
    spki_sha256: str | None = None

    def matches(self, expected: CertificateIdentity) -> bool:
        if (
            expected.spki_sha256 is None
            and expected.subject_dn is None
            and not expected.sans
        ):
            return False
        if expected.spki_sha256 is not None:
            if self.spki_sha256 is None or not compare_digest(
                self.spki_sha256, expected.spki_sha256
            ):
                return False
        if expected.subject_dn is not None and self.subject_dn != expected.subject_dn:
            return False
        if expected.sans and not set(expected.sans).issubset(self.sans):
            return False
        return True


@dataclass(frozen=True)
class CertVerifiedPeer:
    """The authenticated identity from a matched certificate (mTLS analogue of
    signing.VerifiedPeer)."""

    node_id: str
    identity: CertificateIdentity


class UnauthorizedCertificateIdentity(ValueError):
    """A presented certificate identity failed to match the expected identity."""

    def __init__(self, reason: str = "cert_identity_mismatch") -> None:
        super().__init__(reason)
        self.reason = reason


def verify_certificate_identity(
    presented: CertificateIdentity,
    *,
    node_id: str,
    expected: CertificateIdentity,
) -> CertVerifiedPeer:
    """Bind a presented certificate identity to a host-supplied node_id.

    Purely mechanical: federlet compares `presented` against the host-supplied
    `expected` constraints and, on a match, returns a `CertVerifiedPeer` for the
    host-supplied `node_id`. The host owns which identity maps to which node and
    which CA/trust roots are acceptable. Raises `UnauthorizedCertificateIdentity`
    on mismatch.
    """
    if not presented.matches(expected):
        raise UnauthorizedCertificateIdentity()
    return CertVerifiedPeer(node_id=node_id, identity=presented)
