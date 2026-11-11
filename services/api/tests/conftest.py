from __future__ import annotations

import os

import pytest

from app.api import build_app
from app.config import Settings
from app.db import Database
from app.guardians import GuardianService
from tests.fake_registry import FakeRegistry


@pytest.fixture(scope="session")
def database():
    url = os.environ.get("TEST_DATABASE_URL", "postgresql://sss:sss@127.0.0.1:5433/sss")
    db = Database(url, min_size=1, max_size=4)
    db.open()
    db.migrate()
    yield db
    db.close()


@pytest.fixture(autouse=True)
def clean(database):
    with database.connection() as conn:
        conn.execute(
            "TRUNCATE challenges, sessions, guardian_envelopes, share_requests, relay_locks, guardians"
        )
    yield


@pytest.fixture
def registry() -> FakeRegistry:
    return FakeRegistry()


@pytest.fixture
def guardians(database) -> GuardianService:
    service = GuardianService(database, count=5)
    service.seed()
    return service


@pytest.fixture
def settings() -> Settings:
    return Settings(
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        rpc_url="http://127.0.0.1:8545",
        database_url=os.environ.get("TEST_DATABASE_URL", "postgresql://sss:sss@127.0.0.1:5433/sss"),
        challenge_ttl_seconds=120,
        session_ttl_seconds=900,
    )


@pytest.fixture
def app(registry, database, guardians, settings):
    return build_app(registry, database, guardians, settings)
