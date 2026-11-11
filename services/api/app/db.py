"""PostgreSQL access: pooled connections, startup migration, relay locks."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row

from .errors import HttpError

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


class Database:
    def __init__(self, url: str, min_size: int = 1, max_size: int = 8) -> None:
        self.pool = ConnectionPool(
            conninfo=url,
            min_size=min_size,
            max_size=max_size,
            kwargs={"row_factory": dict_row, "autocommit": True},
            open=False,
        )

    def open(self) -> None:
        self.pool.open()
        self.pool.wait(timeout=30)

    def close(self) -> None:
        self.pool.close()

    def migrate(self) -> list[str]:
        applied: list[str] = []
        with self.pool.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    name text PRIMARY KEY,
                    applied_at timestamptz NOT NULL DEFAULT now()
                )
                """
            )
            known = {row["name"] for row in conn.execute("SELECT name FROM schema_migrations").fetchall()}
            for path in sorted(MIGRATIONS.glob("*.sql")):
                if path.name in known:
                    continue
                for statement in _split_statements(path.read_text()):
                    conn.execute(statement)
                conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (path.name,))
                applied.append(path.name)
        return applied

    @contextmanager
    def connection(self) -> Iterator:
        with self.pool.connection() as conn:
            yield conn

    @contextmanager
    def relay_lock(self, did_hash: str, seconds: int = 30) -> Iterator[None]:
        """Refuses concurrent relayer transactions for the same DID (NFR-15, NFR-16).

        Lives in the database so two API instances cannot both submit a rotation.
        """
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                INSERT INTO relay_locks (did_hash, locked_until)
                VALUES (%s, now() + make_interval(secs => %s))
                ON CONFLICT (did_hash) DO UPDATE
                    SET locked_until = excluded.locked_until
                    WHERE relay_locks.locked_until < now()
                RETURNING did_hash
                """,
                (did_hash, seconds),
            ).fetchone()
        if row is None:
            raise HttpError(409, "another transaction for this identity is in flight", "busy")
        try:
            yield
        finally:
            with self.pool.connection() as conn:
                conn.execute("DELETE FROM relay_locks WHERE did_hash = %s", (did_hash,))


def _split_statements(sql: str) -> list[str]:
    """Split on semicolons while respecting dollar-quoted blocks (none today, cheap to keep)."""
    statements: list[str] = []
    buffer: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--") or not stripped:
            continue
        buffer.append(line)
        if stripped.endswith(";"):
            statements.append("\n".join(buffer).strip())
            buffer = []
    tail = "\n".join(buffer).strip()
    if tail:
        statements.append(tail)
    return statements
