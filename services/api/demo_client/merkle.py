"""Merkle commitments and share envelopes — the client side of the commitment scheme."""

from __future__ import annotations

from dataclasses import dataclass

from eth_utils import keccak

from .sss import Share, commitment_of


@dataclass(frozen=True)
class ShareProof:
    index: int
    leaf: str
    siblings: list[str]


def _hash_pair(left: bytes, right: bytes) -> bytes:
    a, b = (left, right) if left.hex() <= right.hex() else (right, left)
    return keccak(a + b)


def build_tree(shares: list[Share]) -> tuple[bytes, list[list[bytes]]]:
    if not shares:
        raise ValueError("no shares")
    levels: list[list[bytes]] = [[commitment_of(share) for share in shares]]
    current = levels[0]
    while len(current) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            nxt.append(_hash_pair(left, right))
        levels.append(nxt)
        current = nxt
    return current[0], levels


def share_root(shares: list[Share]) -> str:
    root, _ = build_tree(shares)
    return "0x" + root.hex()


def build_proof(shares: list[Share], share_index: int) -> ShareProof:
    _, levels = build_tree(shares)
    position = next((i for i, share in enumerate(shares) if share.index == share_index), -1)
    if position < 0:
        raise ValueError(f"share {share_index} not in set")
    siblings: list[str] = []
    cursor = position
    for level in range(len(levels) - 1):
        nodes = levels[level]
        sibling = cursor + 1 if cursor % 2 == 0 else cursor - 1
        siblings.append((nodes[sibling] if sibling < len(nodes) else nodes[cursor]).hex())
        cursor //= 2
    return ShareProof(index=share_index, leaf=levels[0][position].hex(), siblings=siblings)


def verify_proof(proof: ShareProof, root: str) -> bool:
    cursor = bytes.fromhex(proof.leaf)
    for sibling in proof.siblings:
        cursor = _hash_pair(cursor, bytes.fromhex(sibling))
    return cursor.hex() == root.removeprefix("0x").lower()


def envelope(share: Share, proof: ShareProof, root: str, guardian: str) -> dict:
    return {
        "version": 1,
        "index": share.index,
        "value": "0x" + share.value.to_bytes(32, "big").hex(),
        "proof": {"index": proof.index, "leaf": proof.leaf, "siblings": proof.siblings},
        "root": root,
        "guardian": guardian,
    }


def envelope_share(env: dict) -> Share:
    if env.get("version") != 1:
        raise ValueError("unsupported envelope version")
    return Share(index=int(env["index"]), value=int(str(env["value"]), 16))
