"""Device-side client used by the tests and the end-to-end demo.

This is the reference implementation of what happens in the browser: generate
keys, split the recovery secret, seal one envelope per guardian, sign the
registration digest, and later pull k rewrapped shares, verify them against the
on-chain root, reconstruct locally and sign the rotation.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from eth_utils import keccak

from .merkle import build_proof, envelope, envelope_share, share_root, verify_proof
from app.sealing import generate_keypair, open_sealed, seal
from .sss import Share, combine_shares, random_scalar, recovery_address, split_secret


def did_hash(did: str) -> str:
    return "0x" + keccak(did.lower().encode()).hex()


def new_did() -> str:
    return "did:sss:0x" + secrets.token_hex(20)


@dataclass
class Identity:
    did: str
    did_hash: str
    auth_private_key: str
    auth_address: str
    recovery_secret: int
    recovery_address: str
    share_root: str
    threshold: int
    share_count: int
    register_tx: str = ""
    version: int = 1
    pending: dict | None = None
    _shares: list[Share] | None = field(default=None, repr=False)


def create_material(threshold: int, share_count: int) -> tuple[int, list[Share], str]:
    secret = random_scalar()
    shares = split_secret(secret, threshold, share_count)
    return secret, shares, share_root(shares)


def seal_local_shares(
    shares: list[Share], guardians: list[dict], root: str
) -> list[dict]:
    """Seal one envelope per guardian, in an order the device picks at random.

    The device never publishes which share went where: the only artifact that
    leaves it is a list of ciphertexts addressed to guardian public keys.
    """
    order = list(range(len(shares)))
    secrets.SystemRandom().shuffle(order)
    out: list[dict] = []
    for position, share in enumerate(shares):
        guardian = guardians[order[position] % len(guardians)]
        proof = build_proof(shares, share.index)
        payload = envelope(share, proof, root, guardian["id"])
        import json

        sealed = seal(json.dumps(payload).encode(), bytes.fromhex(guardian["publicKey"][2:]))
        out.append({"guardianId": guardian["id"], "ciphertext": "0x" + sealed.hex()})
    return out


def sign_digest(private_key: str, digest: str) -> str:
    signed = Account.sign_message(encode_defunct(hexstr=digest), private_key=private_key)
    return signed.signature.hex() if isinstance(signed.signature, (bytes, bytearray)) else str(signed.signature)


def sign_login(typed_data: dict, private_key: str) -> str:
    signed = Account.sign_message(encode_typed_data(full_message=_full_typed_data(typed_data)), private_key)
    return signed.signature.hex() if isinstance(signed.signature, (bytes, bytearray)) else str(signed.signature)


def _full_typed_data(typed_data: dict) -> dict:
    return {
        "types": {
            **typed_data["types"],
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
        },
        "primaryType": "Login",
        "domain": typed_data["domain"],
        "message": typed_data["message"],
    }


def normalize_signature(signature) -> str:
    if hasattr(signature, "signature"):  # eth_account SignedMessage
        signature = signature.signature
    if isinstance(signature, (bytes, bytearray)):
        return "0x" + bytes(signature).hex()
    text = str(signature)
    return text if text.startswith("0x") else "0x" + text


async def register_identity(
    client,
    threshold: int = 3,
    share_count: int = 5,
) -> Identity:
    account = Account.create()
    did = new_did()
    secret, shares, root = create_material(threshold, share_count)

    payload = {
        "did": did,
        "didHash": did_hash(did),
        "authKey": account.address,
        "recoveryKey": recovery_address(secret),
        "shareRoot": root,
        "threshold": threshold,
        "shareCount": share_count,
    }
    prepared = await client.post("/api/identity/prepare", json=payload)
    prepared.raise_for_status()
    signature = normalize_signature(sign_digest(account.key.hex(), prepared.json()["digest"]))

    registered = await client.post("/api/identity/register", json={**payload, "signature": signature})
    registered.raise_for_status()
    identity = Identity(
        did=did,
        did_hash=payload["didHash"],
        auth_private_key=account.key.hex(),
        auth_address=account.address,
        recovery_secret=secret,
        recovery_address=payload["recoveryKey"],
        share_root=root,
        threshold=threshold,
        share_count=share_count,
        register_tx=registered.json()["txHash"],
        _shares=shares,
    )

    guardians = (await client.get("/api/guardians")).json()["guardians"]
    envelopes = seal_local_shares(shares, guardians, root)
    deposited = await client.post(
        "/api/shares/deposit",
        json={"did": did, "shareRoot": root, "envelopes": envelopes},
    )
    deposited.raise_for_status()
    # The device keeps no share set after distribution.
    identity._shares = None
    return identity


async def complete_recovery(client, identity: Identity, private_key: str, new_private_key: str) -> dict:
    import json

    prepared = await client.post("/api/recovery/prepare", json={"did": identity.did})
    prepared.raise_for_status()
    body = prepared.json()
    threshold = body["request"]["threshold"]

    transport_private, transport_public = _transport_keypair()
    response = await client.post(
        "/api/recovery/shares",
        json={
            "did": identity.did,
            "transportPublicKey": "0x" + transport_public.hex(),
            "count": threshold,
        },
    )
    response.raise_for_status()
    bundles = response.json()["shares"]
    if len(bundles) < threshold:
        raise RuntimeError(f"network returned {len(bundles)} shares, need {threshold}")

    shares: list[Share] = []
    for bundle in bundles:
        plaintext = open_sealed(bytes.fromhex(bundle["ciphertext"][2:]), transport_private)
        payload = json.loads(plaintext)
        if not verify_proof(_proof(payload), body["document"]["shareRoot"]):
            raise RuntimeError(f"share from {bundle['label']} failed Merkle verification")
        shares.append(envelope_share(payload))

    secret = combine_shares(shares)
    if recovery_address(secret) != body["document"]["recoveryKey"]:
        raise RuntimeError("reconstructed secret does not match the on-chain recovery key")

    recovery_account = Account.from_key(secret.to_bytes(32, "big"))
    signature = normalize_signature(sign_digest(recovery_account.key.hex(), body["digest"]))
    executed = await client.post(
        "/api/recovery/execute",
        json={"did": identity.did, "requestId": body["request"]["requestId"], "signature": signature},
    )
    executed.raise_for_status()
    return executed.json()


def _proof(payload: dict):
    from .merkle import ShareProof

    return ShareProof(
        index=payload["proof"]["index"],
        leaf=payload["proof"]["leaf"],
        siblings=list(payload["proof"]["siblings"]),
    )


def _transport_keypair() -> tuple[bytes, bytes]:
    from app.sealing import generate_keypair

    return generate_keypair()
