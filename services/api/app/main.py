"""Entrypoint: `python -m app.main` (or `uv run uvicorn app.main:app`)."""

from __future__ import annotations

import os

import uvicorn

from .api import build_app
from .chain import Web3Registry
from .config import Settings
from .db import Database
from .guardians import GuardianService


def create() -> object:
    settings = Settings()
    if not settings.contract_address:
        raise SystemExit("CONTRACT_ADDRESS is required (deploy with packages/contracts/scripts/deploy.ts)")

    db = Database(settings.database_url)
    db.open()
    applied = db.migrate()
    if applied:
        print(f"[api] applied migrations: {', '.join(applied)}")

    adapter = Web3Registry(
        rpc_url=settings.rpc_url,
        contract_address=settings.contract_address,
        relayer_private_key=settings.relayer_private_key,
    )

    guardians = GuardianService(db, settings.guardian_count)
    guardians.seed()

    app = build_app(adapter, db, guardians, settings)
    app.state.db = db
    print(
        f"[api] chain {adapter.chain_id} | registry {adapter.registry_address} | "
        f"relayer {adapter.relayer_address} | recovery delay {adapter.recovery_delay}s | "
        f"guardians {settings.guardian_count}"
    )
    return app


app = create()

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("HOST", "127.0.0.1"),
        port=Settings().port,
        log_level="info",
    )
