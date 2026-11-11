"""End-to-end story against a real QBFT (Besu) chain and the real API.

Runs the device side for real: keys are generated here, shares are sealed here,
the secret is reconstructed here, and every relayed transaction is signed by the
key that is supposed to sign it. Exits non-zero on the first failed assertion.

    python scripts/e2e_demo.py            # API_URL=http://127.0.0.1:8788
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_client import client as demo  # noqa: E402
from demo_client.client import _full_typed_data, _proof  # noqa: E402
from demo_client.merkle import verify_proof  # noqa: E402
from demo_client.sss import combine_shares  # noqa: E402

API = os.environ.get("API_URL", "http://127.0.0.1:8788")
PASS, FAIL = "\033[32m✓\033[0m", "\033[31m✗\033[0m"
failures = 0


def step(number: str, title: str) -> None:
    print(f"\n\033[1m{number} · {title}\033[0m")


def check(condition: bool, message: str) -> None:
    global failures
    print(f"   {PASS if condition else FAIL} {message}")
    if not condition:
        failures += 1


async def main() -> int:
    async with httpx.AsyncClient(base_url=API, timeout=60) as http:
        health = (await http.get("/api/health")).json()
        step("01", "Registry dan jaringan")
        print(f"   chain id                  {health['chainId']}")
        print(f"   registry                  {health['registry']}")
        print(f"   relayer                   {health['relayer']}")
        print(f"   timelock                  {health['recoveryDelay']}s")
        check(health["chainId"] == 1337, "terhubung ke jaringan QBFT (chainId 1337)")

        step("02", "Registrasi identitas + sebar share")
        identity = await demo.register_identity(http, 3, 5)
        document = (await http.get(f"/api/did/{identity.did}")).json()["document"]
        shares = (await http.get(f"/api/shares/{identity.did}")).json()
        print(f"   DID                       {identity.did}")
        print(f"   auth key                  {identity.auth_address}")
        print(f"   recovery key              {identity.recovery_address}")
        print(f"   share root                {identity.share_root}")
        print(f"   share tersimpan           {shares['count']} (tersegel, acak)")
        print(f"   registrasi tx             {identity.register_tx}")
        check(document["version"] == 1, "dokumen DID tercatat versi 1")
        check(shares["count"] == 5, "5 share tersegel di mailbox guardian")
        check(identity._shares is None, "perangkat tidak menyimpan share setelah distribusi")

        step("03", "Login di dua aplikasi dengan DID yang sama")
        sessions = {}
        for app_id, label in (("klinik", "Portal Klinik"), ("market", "Pasar Digital")):
            challenge = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": app_id})).json()
            signature = demo.normalize_signature(
                Account.sign_message(
                    encode_typed_data(full_message=_full_typed_data(challenge["typedData"])),
                    identity.auth_private_key,
                )
            )
            started = time.perf_counter()
            verified = await http.post(
                "/api/auth/verify",
                json={"challengeId": challenge["challengeId"], "signature": signature},
            )
            elapsed = (time.perf_counter() - started) * 1000
            check(verified.status_code == 200, f"{label} menerima login ({elapsed:.0f} ms)")
            sessions[app_id] = verified.json()["session"]

        step("04", "Signature aplikasi lain ditolak")
        challenge = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "klinik"})).json()
        tampered = {**challenge["typedData"], "message": {**challenge["typedData"]["message"], "app": "market"}}
        cross_signature = demo.normalize_signature(
            Account.sign_message(
                encode_typed_data(full_message=_full_typed_data(tampered)), identity.auth_private_key
            )
        )
        cross = await http.post(
            "/api/auth/verify",
            json={"challengeId": challenge["challengeId"], "signature": cross_signature},
        )
        check(cross.status_code == 401, "challenge terikat app: signature pasar ditolak di klinik")

        step("05", "Perangkat hilang")
        challenge = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "klinik"})).json()
        without_key = Account.create()
        forged = demo.normalize_signature(
            Account.sign_message(
                encode_typed_data(full_message=_full_typed_data(challenge["typedData"])), forged_key := without_key.key
            )
        )
        rejected = await http.post(
            "/api/auth/verify", json={"challengeId": challenge["challengeId"], "signature": forged}
        )
        print(f"   kunci perangkat            dihapus (simulasi)")
        print(f"   share guardian             {shares['count']} tetap tersimpan")
        check(rejected.status_code == 401, "login tanpa kunci valid ditolak (401)")

        step("06", "Membuka permintaan pemulihan")
        new_account = Account.create()
        new_secret, _new_shares, new_root = demo.create_material(3, 5)
        initiated = await http.post(
            "/api/recovery/initiate",
            json={
                "did": identity.did,
                "newAuthKey": new_account.address,
                "newRecoveryKey": demo.recovery_address(new_secret),
                "newShareRoot": new_root,
                "threshold": 3,
                "shareCount": 5,
            },
        )
        initiated.raise_for_status()
        request = initiated.json()
        print(f"   request id                 {request['requestId']}")
        print(f"   eksekusi setelah           {time.strftime('%H:%M:%S', time.localtime(request['executeAfter']))}")
        still_old = (await http.get(f"/api/did/{identity.did}")).json()["document"]
        check(still_old["authKey"].lower() == identity.auth_address.lower(), "permintaan terbuka, dokumen belum berubah")

        step("07", "Kumpulkan k share dan rekonstruksi di perangkat")
        prepared = (await http.post("/api/recovery/prepare", json={"did": identity.did})).json()
        transport_private, transport_public = demo.generate_keypair()
        bundle = (
            await http.post(
                "/api/recovery/shares",
                json={
                    "did": identity.did,
                    "transportPublicKey": "0x" + transport_public.hex(),
                    "count": 3,
                },
            )
        ).json()
        reconstructed = []
        for share in bundle["shares"]:
            payload = json.loads(
                __import__("app.sealing", fromlist=["open_sealed"]).open_sealed(
                    bytes.fromhex(share["ciphertext"][2:]), transport_private
                )
            )
            check(verify_proof(_proof(payload), prepared["document"]["shareRoot"]), f"share {share['label']} lolos verifikasi Merkle")
            reconstructed.append(demo.envelope_share(payload))

        secret = combine_shares(reconstructed)
        check(demo.recovery_address(secret) == prepared["document"]["recoveryKey"], "secret direkonstruksi cocok recovery key on-chain")
        check(combine_shares(reconstructed[:2]) != secret, "2 share saja menghasilkan secret yang salah (ambang bekerja)")

        step("08", "Menandatangani rotasi dan mengeksekusi")
        remaining = prepared["request"]["executeAfter"] - int(time.time()) + 2
        if remaining > 0:
            print(f"   menunggu timelock          {remaining}s")
            time.sleep(remaining)
        recovery_account = Account.from_key(secret.to_bytes(32, "big"))
        signature = demo.normalize_signature(
            Account.sign_message(encode_defunct(hexstr=prepared["digest"]), recovery_account.key)
        )
        executed = await http.post(
            "/api/recovery/execute",
            json={
                "did": identity.did,
                "requestId": prepared["request"]["requestId"],
                "signature": signature,
            },
        )
        executed.raise_for_status()
        rotated = executed.json()["document"]
        print(f"   versi dokumen              {rotated['version']}")
        print(f"   auth key baru              {rotated['authKey']}")
        check(rotated["version"] == 2, "dokumen naik ke versi 2")
        check(rotated["authKey"].lower() == new_account.address.lower(), "auth key dirotasi ke kunci baru")

        step("09", "Verifikasi pasca-pemulihan")
        challenge_old = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "klinik"})).json()
        old_signature = demo.normalize_signature(
            Account.sign_message(
                encode_typed_data(full_message=_full_typed_data(challenge_old["typedData"])),
                identity.auth_private_key,
            )
        )
        old_attempt = await http.post(
            "/api/auth/verify", json={"challengeId": challenge_old["challengeId"], "signature": old_signature}
        )
        check(old_attempt.status_code == 401, "kunci lama ditolak (401)")

        challenge_new = (await http.post("/api/auth/challenge", json={"did": identity.did, "appId": "market"})).json()
        new_signature = demo.normalize_signature(
            Account.sign_message(
                encode_typed_data(full_message=_full_typed_data(challenge_new["typedData"])),
                new_account.key,
            )
        )
        new_attempt = await http.post(
            "/api/auth/verify", json={"challengeId": challenge_new["challengeId"], "signature": new_signature}
        )
        check(new_attempt.status_code == 200, "kunci baru diterima di aplikasi yang sama")

        step("10", "Audit trail on-chain")
        events = (await http.get(f"/api/audit/{identity.did}")).json()["events"]
        for event in events:
            print(f"   {event['type']:<20} {event['txHash'][:18]}…")
        check(len(events) >= 4, f"{len(events)} event tercatat, termasuk eksekusi dan rotasi")

    print()
    if failures:
        print(f"\033[31m{failures} langkah GAGAL\033[0m")
        return 1
    print("\033[32mSEMUA LANGKAH LULUS\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
