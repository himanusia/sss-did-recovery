"""Chain adapter: reads the registry and relays signed transactions with web3.py.

The relayer pays gas for every state change, but authority always comes from an
off-chain signature checked by the contract. Nothing in this module holds a
user's authentication or recovery key.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from web3 import Web3
from web3.exceptions import ContractLogicError, Web3Exception
from web3.middleware import ExtraDataToPOAMiddleware

from .errors import ContractRevert

ABI_PATH = Path(__file__).resolve().parent / "did_registry_abi.json"
ABI = json.loads(ABI_PATH.read_text())
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def _addr(value: str) -> str:
    """web3 refuses non-checksummed addresses; the browser produces lowercase ones."""
    return Web3.to_checksum_address(value)


class RegistryAdapter(Protocol):
    chain_id: int
    registry_address: str
    relayer_address: str
    recovery_delay: int

    def get_document(self, did_hash: str) -> dict | None: ...
    def get_recovery(self, did_hash: str) -> dict | None: ...
    def get_audit(self, did_hash: str) -> list[dict]: ...
    def register_digest(self, params: dict) -> str: ...
    def recovery_digest(self, did_hash: str, request: dict) -> str: ...
    def cancel_digest(self, did_hash: str, request_id: str) -> str: ...
    def register(self, params: dict, signature: str) -> dict: ...
    def initiate_recovery(self, params: dict) -> dict: ...
    def execute_recovery(self, did_hash: str, request_id: str, signature: str) -> dict: ...
    def cancel_recovery(self, did_hash: str, request_id: str, signature: str) -> dict: ...


class Web3Registry:
    def __init__(self, rpc_url: str, contract_address: str, relayer_private_key: str) -> None:
        if not Web3.is_address(contract_address):
            raise SystemExit(f"CONTRACT_ADDRESS is not an address: {contract_address!r}")
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
        # QBFT/IBFT blocks carry a validator set in extraData; without this the
        # block formatter rejects every block as malformed.
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise SystemExit(f"cannot reach an EVM node at {rpc_url}")
        if self.w3.eth.get_code(contract_address) in (b"", b"0x"):
            raise SystemExit(f"no contract deployed at {contract_address}")

        self.contract = self.w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=ABI)
        self.account = self.w3.eth.account.from_key(relayer_private_key)
        self.chain_id = self.w3.eth.chain_id
        self.registry_address = Web3.to_checksum_address(contract_address)
        self.relayer_address = self.account.address
        self.recovery_delay = int(self.contract.functions.recoveryDelay().call())

    # ---------------------------------------------------------------- reads
    def get_document(self, did_hash: str) -> dict | None:
        raw = self.contract.functions.getDocument(did_hash).call()
        auth_key = raw[0]
        if auth_key == ZERO_ADDRESS:
            return None
        return {
            "didHash": did_hash,
            "authKey": Web3.to_checksum_address(auth_key),
            "recoveryKey": Web3.to_checksum_address(raw[1]),
            "shareRoot": Web3.to_hex(raw[2]),
            "threshold": int(raw[3]),
            "shareCount": int(raw[4]),
            "createdAt": int(raw[5]),
            "updatedAt": int(raw[6]),
            "version": int(raw[7]),
            "active": bool(raw[8]),
        }

    def get_recovery(self, did_hash: str) -> dict | None:
        raw = self.contract.functions.getRecovery(did_hash).call()
        if int(raw[5]) == 0:  # requestedAt
            return None
        request_id = int(self.contract.functions.recoveryRequestCount(did_hash).call())
        return {
            "requestId": str(request_id),
            "newAuthKey": Web3.to_checksum_address(raw[0]),
            "newRecoveryKey": Web3.to_checksum_address(raw[1]),
            "newShareRoot": Web3.to_hex(raw[2]),
            "threshold": int(raw[3]),
            "shareCount": int(raw[4]),
            "requestedAt": int(raw[5]),
            "executeAfter": int(raw[6]),
            "executed": bool(raw[7]),
            "cancelled": bool(raw[8]),
        }

    def get_audit(self, did_hash: str) -> list[dict]:
        events: list[dict] = []

        def collect(event_name: str, kind: str, mapper) -> None:
            event = getattr(self.contract.events, event_name)
            logs = event.get_logs(from_block=0, to_block="latest", argument_filters={"didHash": did_hash})
            for log in logs:
                args = log["args"]
                events.append(
                    {
                        "type": kind,
                        "didHash": Web3.to_hex(args["didHash"]),
                        "txHash": Web3.to_hex(log["transactionHash"]),
                        "blockNumber": int(log["blockNumber"]),
                        "logIndex": int(log["logIndex"]),
                        "timestamp": None,
                        "data": mapper(args),
                    }
                )

        collect(
            "DIDRegistered",
            "registered",
            lambda a: {
                "authKey": Web3.to_checksum_address(a["authKey"]),
                "recoveryKey": Web3.to_checksum_address(a["recoveryKey"]),
                "shareRoot": Web3.to_hex(a["shareRoot"]),
                "threshold": int(a["threshold"]),
                "shareCount": int(a["shareCount"]),
            },
        )
        collect(
            "RecoveryInitiated",
            "recovery-initiated",
            lambda a: {
                "requestId": str(a["requestId"]),
                "newAuthKey": Web3.to_checksum_address(a["newAuthKey"]),
                "executeAfter": int(a["executeAfter"]),
            },
        )
        collect("RecoveryCancelled", "recovery-cancelled", lambda a: {"requestId": str(a["requestId"])})
        collect(
            "RecoveryExecuted",
            "recovery-executed",
            lambda a: {
                "requestId": str(a["requestId"]),
                "newAuthKey": Web3.to_checksum_address(a["newAuthKey"]),
                "version": int(a["version"]),
            },
        )
        collect(
            "KeyRotated",
            "key-rotated",
            lambda a: {
                "oldAuthKey": Web3.to_checksum_address(a["oldAuthKey"]),
                "newAuthKey": Web3.to_checksum_address(a["newAuthKey"]),
                "version": int(a["version"]),
            },
        )

        events.sort(key=lambda e: (e["blockNumber"], e["logIndex"]))
        cache: dict[int, int] = {}
        for event in events:
            block = event["blockNumber"]
            if block not in cache:
                cache[block] = int(self.w3.eth.get_block(block)["timestamp"])
            event["timestamp"] = cache[block]
        return events

    # -------------------------------------------------------------- digests
    def register_digest(self, params: dict) -> str:
        return Web3.to_hex(
            self.contract.functions.registerDigest(
                params["didHash"],
                _addr(params["authKey"]),
                _addr(params["recoveryKey"]),
                params["shareRoot"],
                params["threshold"],
                params["shareCount"],
            ).call()
        )

    def recovery_digest(self, did_hash: str, request: dict) -> str:
        return Web3.to_hex(
            self.contract.functions.recoveryDigest(
                did_hash,
                int(request["requestId"]),
                _addr(request["newAuthKey"]),
                _addr(request["newRecoveryKey"]),
                request["newShareRoot"],
                request["threshold"],
                request["shareCount"],
            ).call()
        )

    def cancel_digest(self, did_hash: str, request_id: str) -> str:
        return Web3.to_hex(self.contract.functions.cancelDigest(did_hash, int(request_id)).call())

    # ------------------------------------------------------------ relaying
    def _send(self, fn: Any) -> dict:
        tx = fn.build_transaction(
            {
                "from": self.account.address,
                "nonce": self.w3.eth.get_transaction_count(self.account.address, "pending"),
                "chainId": self.chain_id,
            }
        )
        signed = self.w3.eth.account.sign_transaction(tx, self.account.key)
        try:
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        except (ContractLogicError, Web3Exception, ValueError) as error:
            raise ContractRevert(str(error)) from error
        if receipt["status"] != 1:
            raise ContractRevert(f"transaction reverted: {Web3.to_hex(tx_hash)}")
        return {"txHash": Web3.to_hex(tx_hash)}

    def register(self, params: dict, signature: str) -> dict:
        return self._send(
            self.contract.functions.register(
                params["didHash"],
                _addr(params["authKey"]),
                _addr(params["recoveryKey"]),
                params["shareRoot"],
                params["threshold"],
                params["shareCount"],
                bytes.fromhex(signature.removeprefix("0x")),
            )
        )

    def initiate_recovery(self, params: dict) -> dict:
        result = self._send(
            self.contract.functions.initiateRecovery(
                params["didHash"],
                _addr(params["newAuthKey"]),
                _addr(params["newRecoveryKey"]),
                params["newShareRoot"],
                params["threshold"],
                params["shareCount"],
            )
        )
        request_id = int(self.contract.functions.recoveryRequestCount(params["didHash"]).call())
        request = self.get_recovery(params["didHash"]) or {}
        return {**result, "requestId": str(request_id), "executeAfter": request.get("executeAfter", 0)}

    def execute_recovery(self, did_hash: str, request_id: str, signature: str) -> dict:
        return self._send(
            self.contract.functions.executeRecovery(
                did_hash, int(request_id), bytes.fromhex(signature.removeprefix("0x"))
            )
        )

    def cancel_recovery(self, did_hash: str, request_id: str, signature: str) -> dict:
        return self._send(
            self.contract.functions.cancelRecovery(
                did_hash, int(request_id), bytes.fromhex(signature.removeprefix("0x"))
            )
        )
