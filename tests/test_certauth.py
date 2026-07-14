"""Tests for the generic certificate-identity auth primitive (pimx-3yq.5)."""

from __future__ import annotations

import pytest

from federlet import (
    CertificateIdentity,
    UnauthorizedCertificateIdentity,
    certificate_thumbprint,
    verify_certificate_identity,
)


def test_certificate_thumbprint_is_sha256_of_der():
    import hashlib

    der = b"\x30\x82fake-der-bytes"
    assert certificate_thumbprint(der) == "sha256:" + hashlib.sha256(der).hexdigest()


def test_verify_binds_matching_thumbprint_to_host_node_id():
    thumb = certificate_thumbprint(b"peer-cert")
    presented = CertificateIdentity(spki_sha256=thumb, subject_dn="CN=node-a")
    expected = CertificateIdentity(spki_sha256=thumb)

    peer = verify_certificate_identity(
        presented, node_id="node:org-a:prod", expected=expected
    )
    assert peer.node_id == "node:org-a:prod"
    assert peer.identity is presented


def test_verify_rejects_thumbprint_mismatch():
    presented = CertificateIdentity(spki_sha256=certificate_thumbprint(b"attacker"))
    expected = CertificateIdentity(spki_sha256=certificate_thumbprint(b"genuine"))
    with pytest.raises(UnauthorizedCertificateIdentity) as exc:
        verify_certificate_identity(presented, node_id="n", expected=expected)
    assert exc.value.reason == "cert_identity_mismatch"


def test_empty_expected_identity_matches_nothing():
    # Fail closed: an all-empty expected must not authenticate any peer.
    presented = CertificateIdentity(subject_dn="CN=whatever")
    assert not presented.matches(CertificateIdentity())
    with pytest.raises(UnauthorizedCertificateIdentity):
        verify_certificate_identity(
            presented, node_id="n", expected=CertificateIdentity()
        )


def test_subject_dn_constraint_must_match_exactly():
    presented = CertificateIdentity(subject_dn="CN=node-a,O=org-a")
    assert presented.matches(CertificateIdentity(subject_dn="CN=node-a,O=org-a"))
    assert not presented.matches(CertificateIdentity(subject_dn="CN=node-b,O=org-a"))


def test_san_constraint_requires_expected_subset():
    presented = CertificateIdentity(
        sans=("node-a.example", "spiffe://org-a/node-a"),
    )
    # every expected SAN present -> match
    assert presented.matches(CertificateIdentity(sans=("spiffe://org-a/node-a",)))
    # an expected SAN the peer does not present -> no match
    assert not presented.matches(CertificateIdentity(sans=("node-b.example",)))


def test_all_constraints_must_hold_together():
    thumb = certificate_thumbprint(b"peer")
    presented = CertificateIdentity(
        subject_dn="CN=node-a",
        sans=("node-a.example",),
        spki_sha256=thumb,
    )
    # thumbprint matches but subject constraint fails -> overall mismatch
    expected = CertificateIdentity(spki_sha256=thumb, subject_dn="CN=node-b")
    assert not presented.matches(expected)
