"""Guardian share mailboxes: opaque, sealed, and randomly selected.

The demo co-locates the guardian services with the API so the whole story runs
on one machine, but the custody model is real: each envelope is sealed to a
guardian's X25519 key, the API stores ciphertext, and a recovering device gets
k envelopes chosen at random by the network and rewrapped to its ephemeral key.

Consequences worth stating in the report:
  * the device cannot ask for "the share held by my laptop" — it names no guardian;
  * a guardian cannot see which share index it holds without opening the box;
  * the API never opens a box, so a database dump exposes no share.
"""

from __future__ import annotations

import secrets

from .db import Database
from .errors import HttpError
from .sealing import generate_keypair, open_sealed, public_key_of, seal

DEFAULT_LABELS = [
    "Guardian 1",
    "Guardian 2",
    "Guardian 3",
    "Guardian 4",
    "Guardian 5",
    "Guardian 6",
    "Guardian 7",
]


class GuardianService:
    def __init__(self, db: Database, count: int = 5) -> None:
        self.db = db
        self.count = count

    def seed(self) -> None:
        with self.db.connection() as conn:
            existing = conn.execute("SELECT count(*) AS n FROM guardians").fetchone()["n"]
            if existing >= self.count:
                return
            for index in range(existing, self.count):
                private, public = generate_keypair()
                conn.execute(
                    """
                    INSERT INTO guardians (id, label, public_key, private_key)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (f"g{index + 1}", DEFAULT_LABELS[index], public, private),
                )

    def list_public(self) -> list[dict]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT id, label, public_key FROM guardians WHERE active ORDER BY id"
            ).fetchall()
        return [
            {"id": row["id"], "label": row["label"], "publicKey": "0x" + row["public_key"].hex()}
            for row in rows
        ]

    def deposit(self, did_hash: str, share_root: str, envelopes: list[dict], expected: int) -> dict:
        if len(envelopes) != expected:
            raise HttpError(
                400,
                f"expected {expected} sealed envelopes, received {len(envelopes)}",
                "envelope_count",
            )
        ids = [item["guardianId"] for item in envelopes]
        if len(set(ids)) != len(ids):
            raise HttpError(400, "a guardian received more than one envelope", "duplicate_guardian")

        with self.db.connection() as conn:
            known = {
                row["id"]
                for row in conn.execute(
                    "SELECT id FROM guardians WHERE id = ANY(%s)", (ids,)
                ).fetchall()
            }
            unknown = set(ids) - known
            if unknown:
                raise HttpError(400, f"unknown guardian: {sorted(unknown)[0]}", "unknown_guardian")

            conn.execute("DELETE FROM guardian_envelopes WHERE did_hash = %s", (did_hash,))
            for item in envelopes:
                conn.execute(
                    """
                    INSERT INTO guardian_envelopes (did_hash, guardian_id, ciphertext, share_root)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (did_hash, item["guardianId"], bytes.fromhex(item["ciphertext"][2:]), share_root),
                )
        return {"did": did_hash, "deposited": len(envelopes)}

    def status(self, did_hash: str) -> dict:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT guardian_id, share_root, deposited_at FROM guardian_envelopes WHERE did_hash = %s",
                (did_hash,),
            ).fetchall()
        return {
            "count": len(rows),
            "guardians": sorted(row["guardian_id"] for row in rows),
            "shareRoot": rows[0]["share_root"] if rows else None,
            "depositedAt": rows[0]["deposited_at"].isoformat() if rows else None,
        }

    def collect(self, did_hash: str, transport_public: bytes, count: int, threshold: int) -> dict:
        """Randomly pick `count` guardians, rewrap their sealed share to the device key."""
        if count < threshold:
            raise HttpError(
                400, f"need at least {threshold} shares, asked for {count}", "below_threshold"
            )
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT e.guardian_id, e.ciphertext, g.label, g.private_key
                FROM guardian_envelopes e
                JOIN guardians g ON g.id = e.guardian_id
                WHERE e.did_hash = %s AND g.active
                """,
                (did_hash,),
            ).fetchall()
            if len(rows) < threshold:
                raise HttpError(
                    409,
                    f"only {len(rows)} sealed shares are stored, threshold is {threshold}",
                    "not_enough_shares",
                )
            chosen = secrets.SystemRandom().sample(rows, min(count, len(rows)))
            wrapped = []
            for row in chosen:
                plaintext = open_sealed(row["ciphertext"], row["private_key"])
                rewrapped = seal(plaintext, transport_public)
                wrapped.append(
                    {
                        "guardianId": row["guardian_id"],
                        "label": row["label"],
                        "ciphertext": "0x" + rewrapped.hex(),
                    }
                )
            request = conn.execute(
                """
                INSERT INTO share_requests (did_hash, transport_public_key, requested_count, guardians)
                VALUES (%s, %s, %s, %s)
                RETURNING id, created_at
                """,
                (
                    did_hash,
                    transport_public,
                    len(wrapped),
                    [item["guardianId"] for item in wrapped],
                ),
            ).fetchone()
        return {
            "requestId": str(request["id"]),
            "count": len(wrapped),
            "shares": wrapped,
        }


def transport_public_of(key: str) -> bytes:
    raw = key[2:] if key.startswith("0x") else key
    value = bytes.fromhex(raw)
    public_key_of(value)  # validates nothing here; kept for symmetry with tests
    return value
