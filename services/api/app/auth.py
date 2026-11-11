"""Challenge/response authentication backed by PostgreSQL.

A challenge is random, single use, short lived and bound to the app id, chain id
and registry address (EIP-712). Sessions are database rows, so a second API
instance sees the same logins and a restart does not mint free access.
"""

from __future__ import annotations

import json
import secrets
import time

from eth_account import Account
from eth_account.messages import encode_typed_data

from .db import Database
from .errors import HttpError

LOGIN_TYPES = [
    {"name": "did", "type": "string"},
    {"name": "app", "type": "string"},
    {"name": "nonce", "type": "bytes32"},
    {"name": "issuedAt", "type": "uint64"},
    {"name": "expiresAt", "type": "uint64"},
]

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


class AuthService:
    def __init__(
        self,
        adapter,
        db: Database,
        apps: dict[str, str],
        chain_id: int,
        registry_address: str,
        challenge_ttl_seconds: int,
        session_ttl_seconds: int,
        clock=time.time,
    ) -> None:
        self.adapter = adapter
        self.db = db
        self.apps = apps
        self.chain_id = chain_id
        self.registry_address = registry_address
        self.challenge_ttl = challenge_ttl_seconds
        self.session_ttl = session_ttl_seconds
        self.clock = clock

    def domain(self) -> dict:
        return {
            "name": "SSS DID Auth",
            "version": "1",
            "chainId": self.chain_id,
            "verifyingContract": self.registry_address,
        }

    def require_document(self, did_hash: str) -> dict:
        document = self.adapter.get_document(did_hash)
        if document is None:
            raise HttpError(404, "DID is not registered", "not_registered")
        return document

    def create_challenge(self, did: str, did_hash: str, app_id: str) -> dict:
        app_name = self.apps.get(app_id)
        if app_name is None:
            raise HttpError(400, f"unknown app: {app_id}", "unknown_app")
        document = self.require_document(did_hash)
        if not document["active"]:
            raise HttpError(409, "identity is not active", "inactive")

        issued_at = int(self.clock())
        expires_at = issued_at + self.challenge_ttl
        challenge_id = secrets.token_hex(16)
        nonce = "0x" + secrets.token_hex(32)
        typed_data = {
            "domain": self.domain(),
            "types": {"Login": LOGIN_TYPES},
            "message": {
                "did": did,
                "app": app_id,
                "nonce": nonce,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
            },
        }
        with self.db.connection() as conn:
            conn.execute("DELETE FROM challenges WHERE expires_at <= %s", (issued_at,))
            conn.execute(
                """
                INSERT INTO challenges
                    (id, did, did_hash, app_id, app_name, nonce, typed_data, issued_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                """,
                (
                    challenge_id,
                    did,
                    did_hash,
                    app_id,
                    app_name,
                    nonce,
                    json.dumps(typed_data),
                    issued_at,
                    expires_at,
                ),
            )
        return {
            "challengeId": challenge_id,
            "did": did,
            "appId": app_id,
            "appName": app_name,
            "expiresAt": expires_at * 1000,
            "typedData": typed_data,
        }

    def verify(self, challenge_id: str, signature: str) -> dict:
        now = int(self.clock())
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM challenges WHERE id = %s FOR UPDATE", (challenge_id,)
            ).fetchone()
            if row is None:
                raise HttpError(404, "challenge not found", "unknown_challenge")
            if row["consumed"]:
                raise HttpError(409, "challenge already used", "challenge_used")
            if row["expires_at"] <= now:
                conn.execute("DELETE FROM challenges WHERE id = %s", (challenge_id,))
                raise HttpError(410, "challenge expired", "challenge_expired")

            document = self.require_document(row["did_hash"])
            if not document["active"]:
                raise HttpError(409, "identity is not active", "inactive")

            signer = recover_typed_signer(row["typed_data"], signature)
            if signer is None:
                raise HttpError(400, "malformed signature", "bad_signature")
            if signer.lower() != document["authKey"].lower():
                raise HttpError(
                    401, "signature does not match the authentication key", "bad_signature"
                )

            conn.execute("DELETE FROM challenges WHERE id = %s", (challenge_id,))

            issued_at = int(self.clock() * 1000)
            token = secrets.token_hex(32)
            expires_at = issued_at + self.session_ttl * 1000
            conn.execute(
                """
                INSERT INTO sessions (token, did, app_id, auth_key, issued_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (token, row["did"], row["app_id"], document["authKey"], issued_at, expires_at),
            )

        session = {
            "token": token,
            "did": row["did"],
            "appId": row["app_id"],
            "authKey": document["authKey"],
            "issuedAt": issued_at,
            "expiresAt": expires_at,
        }
        return {"session": session, "authKey": document["authKey"], "version": document["version"]}

    def session(self, token: str | None) -> dict:
        if not token:
            raise HttpError(401, "missing bearer token", "no_session")
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE token = %s", (token,)).fetchone()
            if row is None:
                raise HttpError(401, "unknown session", "no_session")
            if row["expires_at"] <= int(self.clock() * 1000):
                conn.execute("DELETE FROM sessions WHERE token = %s", (token,))
                raise HttpError(401, "session expired", "session_expired")
        return {
            "token": row["token"],
            "did": row["did"],
            "appId": row["app_id"],
            "authKey": row["auth_key"],
            "issuedAt": row["issued_at"],
            "expiresAt": row["expires_at"],
        }

    def logout(self, token: str | None) -> None:
        if not token:
            raise HttpError(401, "missing bearer token", "no_session")
        with self.db.connection() as conn:
            deleted = conn.execute("DELETE FROM sessions WHERE token = %s RETURNING token", (token,)).fetchone()
        if deleted is None:
            raise HttpError(401, "unknown session", "no_session")


def recover_typed_signer(typed_data: dict, signature: str) -> str | None:
    """Recover the EIP-712 signer, tolerating the client sending only the Login type."""
    if not isinstance(signature, str) or not signature.startswith("0x") or len(signature) != 132:
        return None
    full_message = {
        "types": {**typed_data["types"], "EIP712Domain": DOMAIN_FIELDS},
        "primaryType": "Login",
        "domain": typed_data["domain"],
        "message": typed_data["message"],
    }
    try:
        encoded = encode_typed_data(full_message=full_message)
        return Account.recover_message(encoded, signature=signature)
    except (ValueError, TypeError):
        return None
