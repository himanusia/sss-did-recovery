"""Math and encoding: the parts a reviewer can check by hand."""

from __future__ import annotations

import pytest

from app.sealing import generate_keypair, open_sealed, seal
from demo_client.sss import (
    FIELD,
    Share,
    combine_shares,
    random_scalar,
    recovery_address,
    share_token,
    parse_token,
    split_secret,
)
from demo_client.merkle import build_proof, share_root, verify_proof


def test_split_and_combine_round_trip():
    secret = random_scalar()
    shares = split_secret(secret, 3, 5)
    assert combine_shares(shares[:3]) == secret
    assert combine_shares([shares[0], shares[2], shares[4]]) == secret


def test_k_minus_one_shares_do_not_reveal_the_secret():
    secret = random_scalar()
    shares = split_secret(secret, 3, 5)
    assert combine_shares(shares[:2]) != secret


def test_duplicate_indices_are_rejected():
    secret = random_scalar()
    share = split_secret(secret, 2, 3)[0]
    with pytest.raises(ValueError):
        combine_shares([share, share])


def test_shares_are_valid_field_elements():
    for share in split_secret(random_scalar(), 4, 7):
        assert 0 < share.value < FIELD


def test_commitment_root_changes_when_a_share_is_tampered_with():
    shares = split_secret(random_scalar(), 2, 3)
    root = share_root(shares)
    tampered = [shares[0], Share(index=shares[1].index, value=shares[1].value ^ 1), shares[2]]
    assert share_root(tampered) != root

    proof = build_proof(shares, shares[0].index)
    assert verify_proof(proof, root)
    assert not verify_proof(proof, share_root(tampered))


def test_every_share_has_a_verifiable_proof():
    shares = split_secret(random_scalar(), 3, 7)
    root = share_root(shares)
    for share in shares:
        assert verify_proof(build_proof(shares, share.index), root)


def test_recovery_address_is_stable_and_ethereum_shaped():
    secret = random_scalar()
    address = recovery_address(secret)
    assert address == recovery_address(secret)
    assert address.startswith("0x") and len(address) == 42


def test_share_tokens_round_trip():
    share = split_secret(random_scalar(), 2, 3)[0]
    assert parse_token(share_token(share)) == share


def test_sealed_envelope_only_opens_with_the_right_key():
    private, public = generate_keypair()
    other_private, _ = generate_keypair()
    blob = seal(b"share bytes", public)
    assert open_sealed(blob, private) == b"share bytes"
    with pytest.raises(Exception):
        open_sealed(blob, other_private)


def test_ciphertexts_are_unique_even_for_identical_plaintext():
    private, public = generate_keypair()
    first = seal(b"same", public)
    second = seal(b"same", public)
    assert first != second
    assert open_sealed(first, private) == open_sealed(second, private) == b"same"
