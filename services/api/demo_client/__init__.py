"""Device-side helpers used by the tests and the end-to-end demo."""

from .client import (
    Identity,
    complete_recovery,
    create_material,
    did_hash,
    new_did,
    register_identity,
    seal_local_shares,
    sign_digest,
    sign_login,
)
from .merkle import ShareProof, build_proof, envelope, envelope_share, share_root, verify_proof
from app.sealing import generate_keypair, open_sealed, seal
from .sss import Share, combine_shares, recovery_address, split_secret

__all__ = [
    "Identity",
    "Share",
    "ShareProof",
    "build_proof",
    "combine_shares",
    "complete_recovery",
    "create_material",
    "did_hash",
    "envelope",
    "envelope_share",
    "generate_keypair",
    "new_did",
    "open_sealed",
    "recovery_address",
    "register_identity",
    "seal",
    "seal_local_shares",
    "share_root",
    "sign_digest",
    "sign_login",
    "split_secret",
    "verify_proof",
]
