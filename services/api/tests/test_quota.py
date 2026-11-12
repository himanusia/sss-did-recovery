"""Relayer abuse guard: the per-IP hourly budget."""

from __future__ import annotations

import httpx
import pytest
from eth_account import Account

from app.api import build_app
from app.errors import HttpError
from app.quota import RelayQuota
from demo_client import client as demo


def test_quota_allows_up_to_the_limit(database):
    quota = RelayQuota(database, limit_per_hour=2)
    assert quota.consume("203.0.113.7") == 1
    assert quota.consume("203.0.113.7") == 2
    with pytest.raises(HttpError) as error:
        quota.consume("203.0.113.7")
    assert error.value.status == 429
    assert error.value.code == "relay_quota"


def test_quota_is_per_address(database):
    quota = RelayQuota(database, limit_per_hour=1)
    quota.consume("198.51.100.1")
    quota.consume("198.51.100.2")
    with pytest.raises(HttpError):
        quota.consume("198.51.100.1")


async def test_register_returns_429_when_the_budget_is_spent(registry, database, guardians, settings):
    tight = type(settings)(
        contract_address=settings.contract_address,
        rpc_url=settings.rpc_url,
        database_url=settings.database_url,
        challenge_ttl_seconds=120,
        session_ttl_seconds=900,
        relay_quota_per_hour=1,
    )
    app = build_app(registry, database, guardians, tight)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers={"x-real-ip": "192.0.2.10"}
    ) as client:
        headers = {"x-real-ip": "192.0.2.10"}
        first = await demo.register_identity(client, 2, 3)
        assert first.did.startswith("did:sss:")

        account = Account.create()
        payload = {
            "did": demo.new_did(),
            "didHash": "0x" + "ab" * 32,
            "authKey": account.address,
            "recoveryKey": account.address,
            "shareRoot": "0x" + "cd" * 32,
            "threshold": 2,
            "shareCount": 3,
            "signature": "0x" + "11" * 65,
        }
        # The request never reaches validation: the address already spent its hour.
        blocked = await client.post("/api/identity/register", json=payload, headers=headers)
        assert blocked.status_code == 429
        assert blocked.json()["code"] == "relay_quota"

        # A different address still has budget (and fails validation, not quota).
        other = await client.post(
            "/api/identity/register", json=payload, headers={"x-real-ip": "192.0.2.11"}
        )
        assert other.status_code in (400, 409)
