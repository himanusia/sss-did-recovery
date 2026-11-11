"""Shamir's Secret Sharing over the secp256k1 scalar field (demo client).

Mirrors apps/web and packages/crypto exactly: same field, same share indices,
same commitment construction. This module is used by the pytest suite and by
scripts/e2e_demo.py, which act as the user's device. The API server never
imports it for request handling; it only moves sealed envelopes.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from eth_account import Account
from eth_utils import keccak

FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def mod(value: int, modulus: int = FIELD) -> int:
    return value % modulus


def mod_inverse(value: int, modulus: int = FIELD) -> int:
    if value == 0:
        raise ValueError("inverse of zero")
    return pow(value, modulus - 2, modulus)


def random_scalar() -> int:
    while True:
        candidate = int.from_bytes(secrets.token_bytes(32), "big")
        if 0 < candidate < FIELD:
            return candidate


@dataclass(frozen=True)
class Share:
    index: int
    value: int


def split_secret(secret: int, threshold: int, share_count: int) -> list[Share]:
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if share_count < threshold:
        raise ValueError("shareCount must be >= threshold")
    if share_count > 255:
        raise ValueError("shareCount must be <= 255")
    if not 0 < secret < FIELD:
        raise ValueError("secret out of field range")

    coefficients = [secret] + [random_scalar() for _ in range(threshold - 1)]
    shares: list[Share] = []
    for index in range(1, share_count + 1):
        value = 0
        power = 1
        for coefficient in coefficients:
            value = mod(value + coefficient * power)
            power = mod(power * index)
        shares.append(Share(index=index, value=value))
    return shares


def combine_shares(shares: list[Share]) -> int:
    if not shares:
        raise ValueError("no shares provided")
    seen: set[int] = set()
    for share in shares:
        if not 1 <= share.index <= 255:
            raise ValueError(f"invalid share index: {share.index}")
        if not 0 < share.value < FIELD:
            raise ValueError("share value out of range")
        if share.index in seen:
            raise ValueError(f"duplicate share index: {share.index}")
        seen.add(share.index)

    secret = 0
    for share in shares:
        numerator = 1
        denominator = 1
        for other in shares:
            if other.index == share.index:
                continue
            numerator = mod(numerator * other.index)
            denominator = mod(denominator * (other.index - share.index))
        secret = mod(secret + share.value * numerator * mod_inverse(denominator))
    return secret


def recovery_address(secret: int) -> str:
    private_key = secret.to_bytes(32, "big")
    return Account.from_key(private_key).address


def commitment_of(share: Share) -> bytes:
    return keccak(bytes([share.index]) + share.value.to_bytes(32, "big"))


def share_token(share: Share) -> str:
    return f"sss1:{share.index}:{share.value.to_bytes(32, 'big').hex()}"


def parse_token(token: str) -> Share:
    parts = token.strip().split(":")
    if len(parts) != 3 or parts[0] != "sss1":
        raise ValueError("invalid share token")
    index = int(parts[1])
    value = int(parts[2], 16)
    if not 1 <= index <= 255 or value <= 0:
        raise ValueError("invalid share token")
    return Share(index=index, value=value)
