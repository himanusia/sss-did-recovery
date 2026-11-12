"""Per-IP budget for transactions the relayer pays for.

nginx already rate-limits the public entry point; this is the second line of
defence, enforced in the API against the real client address (X-Real-IP set by
nginx from CF-Connecting-IP) and stored in PostgreSQL so it holds across API
instances and restarts.
"""

from __future__ import annotations

import time

from .db import Database
from .errors import HttpError


class RelayQuota:
    def __init__(self, db: Database, limit_per_hour: int = 30) -> None:
        self.db = db
        self.limit = limit_per_hour

    def consume(self, ip: str) -> int:
        bucket = int(time.time() // 3600) * 3600
        with self.db.connection() as conn:
            row = conn.execute(
                """
                INSERT INTO relay_quota (ip, bucket, count)
                VALUES (%s, to_timestamp(%s), 1)
                ON CONFLICT (ip, bucket) DO UPDATE
                    SET count = relay_quota.count + 1
                    WHERE relay_quota.count < %s
                RETURNING count
                """,
                (ip, bucket, self.limit),
            ).fetchone()
        if row is None:
            raise HttpError(
                429,
                f"terlalu banyak transaksi dari alamat ini (maks {self.limit}/jam)",
                "relay_quota",
            )
        return int(row["count"])
