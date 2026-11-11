"""Randomised, encrypted share distribution — the part that replaces file downloads."""

from __future__ import annotations

import json

import httpx
import pytest
from eth_account import Account

from demo_client import client as demo
from demo_client.merkle import verify_proof
from demo_client.client import _proof
from demo_client.sss import combine_shares, recovery_address
from app.sealing import open_sealed


@pytest.fixture
async def http(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def test_guardians_have_public_keys_only(http):
    body = (await http.get("/api/guardians")).json()
    assert len(body["guardians"]) == 5
    for guardian in body["guardians"]:
        assert guardian["publicKey"].startswith("0x")
        assert len(guardian["publicKey"]) == 66
        assert "privateKey" not in guardian


async def test_registration_distributes_sealed_shares(http, database):
    identity = await demo.register_identity(http, 3, 5)

    status = (await http.get(f"/api/shares/{identity.did}")).json()
    assert status["count"] == 5
    assert status["shareRoot"].lower() == identity.share_root.lower()

    with database.connection() as conn:
        rows = conn.execute(
            "SELECT ciphertext FROM guardian_envelopes WHERE did_hash = %s", (identity.did_hash,)
        ).fetchall()
    assert len(rows) == 5
    for row in rows:
        blob = bytes(row["ciphertext"])
        assert blob.startswith(b"SD1")
        assert b"sss1:" not in blob  # no plaintext share token
        assert identity.recovery_secret.to_bytes(32, "big") not in blob


async def test_recovery_collects_k_rewrapped_shares_and_reconstructs(http):
    identity = await demo.register_identity(http, 3, 5)
    transport_private, transport_public = demo.generate_keypair()

    response = await http.post(
        "/api/recovery/shares",
        json={
            "did": identity.did,
            "transportPublicKey": "0x" + transport_public.hex(),
            "count": 3,
        },
    )
    assert response.status_code == 200, response.text
    bundle = response.json()
    assert bundle["count"] == 3
    assert len({share["guardianId"] for share in bundle["shares"]}) == 3

    shares = []
    for share in bundle["shares"]:
        payload = json.loads(open_sealed(bytes.fromhex(share["ciphertext"][2:]), transport_private))
        assert verify_proof(_proof(payload), identity.share_root)
        shares.append(demo.envelope_share(payload))

    assert recovery_address(combine_shares(shares)).lower() == identity.recovery_address.lower()


async def test_shares_are_useless_to_a_different_transport_key(http):
    identity = await demo.register_identity(http, 3, 5)
    _private_a, public_a = demo.generate_keypair()
    private_b, _public_b = demo.generate_keypair()

    bundle = (
        await http.post(
            "/api/recovery/shares",
            json={"did": identity.did, "transportPublicKey": "0x" + public_a.hex(), "count": 3},
        )
    ).json()

    with pytest.raises(Exception):
        open_sealed(bytes.fromhex(bundle["shares"][0]["ciphertext"][2:]), private_b)


async def test_deposit_requires_one_envelope_per_share(http):
    identity = await demo.register_identity(http, 3, 5)
    guardians = (await http.get("/api/guardians")).json()["guardians"]
    _secret, shares, _root = demo.create_material(2, 3)
    sealed = demo.seal_local_shares(shares, guardians, identity.share_root)

    short = await http.post(
        "/api/shares/deposit",
        json={"did": identity.did, "shareRoot": identity.share_root, "envelopes": sealed[:2]},
    )
    assert short.status_code == 400
    assert short.json()["code"] == "envelope_count"


async def test_deposit_rejects_an_unregistered_guardian(http):
    identity = await demo.register_identity(http, 3, 5)
    _secret, shares, _root = demo.create_material(3, 5)
    guardians = (await http.get("/api/guardians")).json()["guardians"]
    sealed = demo.seal_local_shares(shares, guardians, identity.share_root)
    sealed[0]["guardianId"] = "g99"

    response = await http.post(
        "/api/shares/deposit",
        json={"did": identity.did, "shareRoot": identity.share_root, "envelopes": sealed},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "unknown_guardian"


async def test_deposit_rejects_two_envelopes_for_the_same_guardian(http):
    identity = await demo.register_identity(http, 3, 5)
    _secret, shares, _root = demo.create_material(3, 5)
    guardians = (await http.get("/api/guardians")).json()["guardians"]
    sealed = demo.seal_local_shares(shares, guardians, identity.share_root)
    sealed[1]["guardianId"] = sealed[0]["guardianId"]

    response = await http.post(
        "/api/shares/deposit",
        json={"did": identity.did, "shareRoot": identity.share_root, "envelopes": sealed},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "duplicate_guardian"


async def test_deposit_rejects_a_root_that_is_not_the_registered_one(http):
    identity = await demo.register_identity(http, 3, 5)
    secret, shares, root = demo.create_material(3, 5)
    guardians = (await http.get("/api/guardians")).json()["guardians"]
    sealed = demo.seal_local_shares(shares, guardians, root)

    response = await http.post(
        "/api/shares/deposit",
        json={"did": identity.did, "shareRoot": "0x" + "99" * 32, "envelopes": sealed},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "root_mismatch"


async def test_collect_refuses_to_go_below_the_threshold(http):
    identity = await demo.register_identity(http, 3, 5)
    _private, public = demo.generate_keypair()
    response = await http.post(
        "/api/recovery/shares",
        json={"did": identity.did, "transportPublicKey": "0x" + public.hex(), "count": 2},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "below_threshold"


async def test_full_recovery_over_the_real_distribution(http, registry):
    identity = await demo.register_identity(http, 3, 5)
    new_account = Account.create()
    new_secret, _new_shares, new_root = demo.create_material(3, 5)

    initiated = await http.post(
        "/api/recovery/initiate",
        json={
            "did": identity.did,
            "newAuthKey": new_account.address,
            "newRecoveryKey": recovery_address(new_secret),
            "newShareRoot": new_root,
            "threshold": 3,
            "shareCount": 5,
        },
    )
    assert initiated.status_code == 201, initiated.text

    executed = await demo.complete_recovery(http, identity, identity.auth_private_key, new_account.key.hex())
    assert executed["document"]["version"] == 2
    assert executed["document"]["authKey"].lower() == new_account.address.lower()
