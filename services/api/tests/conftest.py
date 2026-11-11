from __future__ import annotations

import os

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from app.api import build_app
from app.config import Settings
from app.db import Database
from app.guardians import GuardianService
from tests.fake_registry import FakeRegistry

DEFAULT_TEST_URL = "postgresql://sss:sss@127.0.0.1:5433/sss_test"


def test_database_url() -> str:
    return os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_URL)


def ensure_database(url: str) -> None:
    """Tests own a separate database so they never wipe a running demo's state."""
    info = conninfo_to_dict(url)
    name = info.get("dbname")
    admin = make_conninfo(**{**info, "dbname": "postgres"})
    with psycopg.connect(admin, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone()
        if not exists:
            conn.execute(f'CREATE DATABASE "{name}"')


@pytest.fixture(scope="session")
def database():
    url = test_database_url()
    ensure_database(url)
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
        database_url=test_database_url(),
        challenge_ttl_seconds=120,
        session_ttl_seconds=900,
    )


@pytest.fixture
def app(registry, database, guardians, settings):
    return build_app(registry, database, guardians, settings)
