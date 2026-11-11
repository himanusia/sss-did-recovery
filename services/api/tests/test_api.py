"""HTTP contract: identity, login, session, recovery wiring, audit."""

from __future__ import annotations

import time

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data

from demo_client import client as demo
from demo_client.client import _full_typed_data


@pytest.fixture
async def http(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def register(http, threshold=3, share_count=5):
    return await demo.register_identity(http, threshold, share_count)


async def test_health_reports_chain_and_registry(http):
    response = await http.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["chainId"] == 1337
    assert body["registry"].startswith("0x")
    assert body["apps"]["klinik"] == "Portal Klinik"
    assert body["challengeTtlSeconds"] == 120


async def test_prepare_rejects_a_did_hash_that_does_not_match(http):
    account = Account.create()
    did = demo.new_did()
    payload = {
        "did": did,
        "didHash": "0x" + "11" * 32,
        "authKey": account.address,
        "recoveryKey": account.address,
        "shareRoot": "0x" + "22" * 32,
        "threshold": 2,
        "shareCount": 3,
    }
    response = await http.post("/api/identity/prepare", json=payload)
    assert response.status_code == 400
    assert response.json()["code"] == "did_mismatch"


async def test_register_then_reject_duplicate(http, registry):
    identity = await register(http)
    assert registry.get_document(identity.did_hash)["version"] == 1

    again = await http.post(
        "/api/identity/register",
        json={
            "did": identity.did,
            "didHash": identity.did_hash,
            "authKey": identity.auth_address,
            "recoveryKey": identity.recovery_address,
            "shareRoot": identity.share_root,
            "threshold": 3,
            "shareCount": 5,
            "signature": "0x" + "11" * 65,
        },
    )
    assert again.status_code == 409
    assert again.json()["code"] == "already_registered"


async def test_login_with_the_auth_key_and_reject_replay(http):
    identity = await register(http)
    challenge = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "klinik"})).json()
    signature = demo.normalize_signature(
        Account.sign_message(
            encode_typed_data(full_message=_full_typed_data(challenge["typedData"])),
            identity.auth_private_key,
        ).signature
    )
    verified = await http.post(
        "/api/auth/verify", json={"challengeId": challenge["challengeId"], "signature": signature}
    )
    assert verified.status_code == 200, verified.text
    session = verified.json()["session"]
    assert session["did"] == identity.did

    replay = await http.post(
        "/api/auth/verify", json={"challengeId": challenge["challengeId"], "signature": signature}
    )
    assert replay.status_code == 404


async def test_challenge_is_bound_to_the_app(http):
    identity = await register(http)
    challenge = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "klinik"})).json()

    tampered = dict(challenge["typedData"])
    tampered["message"] = {**tampered["message"], "app": "market"}
    signature = demo.normalize_signature(
        Account.sign_message(
            encode_typed_data(full_message=_full_typed_data(tampered)), identity.auth_private_key
        ).signature
    )
    rejected = await http.post(
        "/api/auth/verify", json={"challengeId": challenge["challengeId"], "signature": signature}
    )
    assert rejected.status_code == 401


async def test_signature_from_another_key_is_rejected(http):
    identity = await register(http)
    stranger = Account.create()
    challenge = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "market"})).json()
    signature = demo.normalize_signature(
        Account.sign_message(
            encode_typed_data(full_message=_full_typed_data(challenge["typedData"])), stranger.key
        ).signature
    )
    rejected = await http.post(
        "/api/auth/verify", json={"challengeId": challenge["challengeId"], "signature": signature}
    )
    assert rejected.status_code == 401
    assert rejected.json()["code"] == "bad_signature"


async def test_expired_challenge_is_refused(http, database):
    identity = await register(http)
    challenge = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "klinik"})).json()
    with database.connection() as conn:
        conn.execute(
            "UPDATE challenges SET expires_at = %s WHERE id = %s",
            (int(time.time()) - 1, challenge["challengeId"]),
        )
    response = await http.post(
        "/api/auth/verify",
        json={"challengeId": challenge["challengeId"], "signature": "0x" + "11" * 65},
    )
    assert response.status_code == 410
    assert response.json()["code"] == "challenge_expired"


async def test_session_and_logout(http):
    identity = await register(http)
    challenge = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "klinik"})).json()
    signature = demo.normalize_signature(
        Account.sign_message(
            encode_typed_data(full_message=_full_typed_data(challenge["typedData"])),
            identity.auth_private_key,
        ).signature
    )
    token = (
        await http.post("/api/auth/verify", json={"challengeId": challenge["challengeId"], "signature": signature})
    ).json()["session"]["token"]

    current = await http.get("/api/auth/session", headers={"Authorization": f"Bearer {token}"})
    assert current.status_code == 200
    assert current.json()["document"]["authKey"].lower() == identity.auth_address.lower()

    assert (await http.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})).status_code == 200
    assert (await http.get("/api/auth/session", headers={"Authorization": f"Bearer {token}"})).status_code == 401


async def test_unknown_app_is_refused(http):
    identity = await register(http)
    response = await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "nope"})
    assert response.status_code == 400
    assert response.json()["code"] == "unknown_app"


async def test_recovery_rejects_the_current_auth_key_as_the_new_one(http):
    identity = await register(http)
    response = await http.post(
        "/api/recovery/initiate",
        json={
            "did": identity.did,
            "newAuthKey": identity.auth_address,
            "newRecoveryKey": identity.recovery_address,
            "newShareRoot": "0x" + "33" * 32,
            "threshold": 3,
            "shareCount": 5,
        },
    )
    assert response.status_code == 400
    assert response.json()["code"] == "same_key"


async def test_recovery_lifecycle_rotates_the_key(http, registry):
    identity = await register(http)
    new_account = Account.create()
    new_secret = demo.create_material(3, 5)[0]

    initiated = await http.post(
        "/api/recovery/initiate",
        json={
            "did": identity.did,
            "newAuthKey": new_account.address,
            "newRecoveryKey": demo.recovery_address(new_secret),
            "newShareRoot": demo.create_material(3, 5)[2],
            "threshold": 3,
            "shareCount": 5,
        },
    )
    assert initiated.status_code == 201, initiated.text
    request_id = initiated.json()["requestId"]

    duplicate = await http.post(
        "/api/recovery/initiate",
        json={
            "did": identity.did,
            "newAuthKey": new_account.address,
            "newRecoveryKey": demo.recovery_address(new_secret),
            "newShareRoot": "0x" + "44" * 32,
            "threshold": 3,
            "shareCount": 5,
        },
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["code"] == "recovery_pending"

    prepared = await http.post("/api/recovery/prepare", json={"did": identity.did})
    assert prepared.status_code == 200
    assert prepared.json()["request"]["requestId"] == request_id
    digest = prepared.json()["digest"]

    # A signature by the wrong key must not execute anything.
    wrong = demo.normalize_signature(
        Account.sign_message(encode_defunct(hexstr=digest), Account.create().key).signature
    )
    refused = await http.post(
        "/api/recovery/execute",
        json={"did": identity.did, "requestId": request_id, "signature": wrong},
    )
    assert refused.status_code == 400
    assert refused.json()["code"] == "contract_rejected"

    recovery_account = Account.from_key(identity.recovery_secret.to_bytes(32, "big"))
    right = demo.normalize_signature(
        Account.sign_message(encode_defunct(hexstr=digest), recovery_account.key).signature
    )
    executed = await http.post(
        "/api/recovery/execute",
        json={"did": identity.did, "requestId": request_id, "signature": right},
    )
    assert executed.status_code == 200, executed.text
    assert executed.json()["document"]["version"] == 2
    assert executed.json()["document"]["authKey"].lower() == new_account.address.lower()


async def test_cancel_path(http, registry):
    identity = await register(http)
    new_account = Account.create()
    await http.post(
        "/api/recovery/initiate",
        json={
            "did": identity.did,
            "newAuthKey": new_account.address,
            "newRecoveryKey": identity.recovery_address,
            "newShareRoot": "0x" + "55" * 32,
            "threshold": 3,
            "shareCount": 5,
        },
    )
    prepared = await http.post("/api/recovery/cancel/prepare", json={"did": identity.did})
    assert prepared.status_code == 200
    cancel_signature = demo.normalize_signature(
        Account.sign_message(encode_defunct(hexstr=prepared.json()["digest"]), identity.auth_private_key).signature
    )
    cancelled = await http.post(
        "/api/recovery/cancel",
        json={
            "did": identity.did,
            "requestId": prepared.json()["requestId"],
            "signature": cancel_signature,
        },
    )
    assert cancelled.status_code == 200
    assert registry.get_recovery(identity.did_hash)["cancelled"] is True


async def test_audit_reads_the_chain_events(http):
    identity = await register(http)
    response = await http.get(f"/api/audit/{identity.did}")
    assert response.status_code == 200
    assert [event["type"] for event in response.json()["events"]] == ["registered"]


async def test_unknown_did_is_404(http):
    did = demo.new_did()
    assert (await http.get(f"/api/did/{did}")).status_code == 404
