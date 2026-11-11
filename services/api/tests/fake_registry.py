"""In-memory registry adapter so the HTTP contract can be tested without a chain.

Signature authority lives in the contract in production; here registration is
accepted as-is and the rest of the lifecycle is modelled faithfully enough to
exercise the API: pending request, timelock, single execution, cancellation,
key rotation and an audit trail.
"""

from __future__ import annotations

import time

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

from app.errors import ContractRevert


def _hex32(*parts) -> str:
    return "0x" + keccak(repr(parts).encode()).hex()


class FakeRegistry:
    def __init__(self, chain_id: int = 1337, recovery_delay: int = 0) -> None:
        self.chain_id = chain_id
        self.registry_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        self.relayer_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        self.recovery_delay = recovery_delay
        self.documents: dict[str, dict] = {}
        self.recoveries: dict[str, dict] = {}
        self.counts: dict[str, int] = {}
        self.events: dict[str, list[dict]] = {}
        self.calls: list[str] = []

    # ---------------------------------------------------------------- reads
    def get_document(self, did_hash: str) -> dict | None:
        return self.documents.get(did_hash.lower())

    def get_recovery(self, did_hash: str) -> dict | None:
        return self.recoveries.get(did_hash.lower())

    @staticmethod
    def _expect(digest: str, signature: str, expected_signer: str) -> None:
        try:
            signer = Account.recover_message(encode_defunct(hexstr=digest), signature=signature)
        except (ValueError, TypeError) as error:
            raise ContractRevert("InvalidSignature") from error
        if signer.lower() != expected_signer.lower():
            raise ContractRevert("InvalidSignature")

    def get_audit(self, did_hash: str) -> list[dict]:
        return list(self.events.get(did_hash.lower(), []))

    # -------------------------------------------------------------- digests
    def register_digest(self, params: dict) -> str:
        subset = {
            key: params[key]
            for key in ("didHash", "authKey", "recoveryKey", "shareRoot", "threshold", "shareCount")
        }
        return _hex32("register", subset)

    def recovery_digest(self, did_hash: str, request: dict) -> str:
        return _hex32("recover", did_hash, request)

    def cancel_digest(self, did_hash: str, request_id: str) -> str:
        return _hex32("cancel", did_hash, request_id)

    # ------------------------------------------------------------- writes
    def register(self, params: dict, signature: str) -> dict:
        self.calls.append("register")
        self._expect(self.register_digest(params), signature, params["authKey"])
        key = params["didHash"].lower()
        now = int(time.time())
        self.documents[key] = {
            "didHash": params["didHash"],
            "authKey": params["authKey"],
            "recoveryKey": params["recoveryKey"],
            "shareRoot": params["shareRoot"],
            "threshold": params["threshold"],
            "shareCount": params["shareCount"],
            "createdAt": now,
            "updatedAt": now,
            "version": 1,
            "active": True,
        }
        self.events.setdefault(key, []).append({"type": "registered", "data": {"authKey": params["authKey"]}})
        return {"txHash": "0x" + "ab" * 32}

    def initiate_recovery(self, params: dict) -> dict:
        self.calls.append("initiateRecovery")
        key = params["didHash"].lower()
        request_id = self.counts.get(key, 0) + 1
        self.counts[key] = request_id
        execute_after = int(time.time()) + self.recovery_delay
        self.recoveries[key] = {
            "requestId": str(request_id),
            "newAuthKey": params["newAuthKey"],
            "newRecoveryKey": params["newRecoveryKey"],
            "newShareRoot": params["newShareRoot"],
            "threshold": params["threshold"],
            "shareCount": params["shareCount"],
            "requestedAt": int(time.time()),
            "executeAfter": execute_after,
            "executed": False,
            "cancelled": False,
        }
        self.events.setdefault(key, []).append(
            {"type": "recovery-initiated", "data": {"requestId": str(request_id)}}
        )
        return {"txHash": "0x" + "cd" * 32, "requestId": str(request_id), "executeAfter": execute_after}

    def execute_recovery(self, did_hash: str, request_id: str, signature: str) -> dict:
        self.calls.append("executeRecovery")
        key = did_hash.lower()
        self._expect(
            self.recovery_digest(did_hash, self.recoveries[key]),
            signature,
            self.documents[key]["recoveryKey"],
        )
        document = self.documents[key]
        request = self.recoveries[key]
        document.update(
            authKey=request["newAuthKey"],
            recoveryKey=request["newRecoveryKey"],
            shareRoot=request["newShareRoot"],
            threshold=request["threshold"],
            shareCount=request["shareCount"],
            version=document["version"] + 1,
            updatedAt=int(time.time()),
        )
        request["executed"] = True
        self.events.setdefault(key, []).append(
            {"type": "recovery-executed", "data": {"version": document["version"]}}
        )
        return {"txHash": "0x" + "ef" * 32}

    def cancel_recovery(self, did_hash: str, request_id: str, signature: str) -> dict:
        self.calls.append("cancelRecovery")
        self._expect(self.cancel_digest(did_hash, request_id), signature, self.documents[did_hash.lower()]["authKey"])
        self.recoveries[did_hash.lower()]["cancelled"] = True
        self.events.setdefault(did_hash.lower(), []).append({"type": "recovery-cancelled", "data": {}})
        return {"txHash": "0x" + "12" * 32}
