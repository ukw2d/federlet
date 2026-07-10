"""Typed signing helpers for standard protocol responses."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import (
    IntroduceResponse,
    MembersResponse,
    RevocationsResponse,
)
from .query import QueryResponse
from .signing import sign_model


def sign_introduce_response(
    response: IntroduceResponse,
    key: Ed25519PrivateKey,
    key_id: str,
) -> IntroduceResponse:
    return sign_model(response, key, key_id)


def sign_members_response(
    response: MembersResponse,
    key: Ed25519PrivateKey,
    key_id: str,
) -> MembersResponse:
    return sign_model(response, key, key_id)


def sign_revocations_response(
    response: RevocationsResponse,
    key: Ed25519PrivateKey,
    key_id: str,
) -> RevocationsResponse:
    return sign_model(response, key, key_id)


def sign_query_response(
    response: QueryResponse,
    key: Ed25519PrivateKey,
    key_id: str,
) -> QueryResponse:
    return sign_model(response, key, key_id)
