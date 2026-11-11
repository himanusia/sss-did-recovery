"""Runtime configuration. Everything is environment driven; no secrets on disk."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_RELAYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEFAULT_APPS = "klinik:Portal Klinik,market:Pasar Digital"


def _parse_apps(value: str) -> dict[str, str]:
    apps: dict[str, str] = {}
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        app_id, _, label = entry.partition(":")
        apps[app_id.strip()] = (label.strip() or app_id.strip())
    return apps


def _positive_int(name: str, fallback: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return fallback
    try:
        value = int(raw)
    except ValueError as error:
        raise SystemExit(f"{name} must be an integer") from error
    if value <= 0:
        raise SystemExit(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class Settings:
    rpc_url: str = field(default_factory=lambda: os.environ.get("RPC_URL", "http://127.0.0.1:8545"))
    contract_address: str = field(default_factory=lambda: os.environ.get("CONTRACT_ADDRESS", ""))
    relayer_private_key: str = field(
        default_factory=lambda: os.environ.get("RELAYER_PRIVATE_KEY", DEFAULT_RELAYER_KEY)
    )
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "DATABASE_URL", "postgresql://sss:sss@127.0.0.1:5433/sss"
        )
    )
    apps: dict[str, str] = field(default_factory=lambda: _parse_apps(os.environ.get("APPS", DEFAULT_APPS)))
    challenge_ttl_seconds: int = field(
        default_factory=lambda: _positive_int("CHALLENGE_TTL_SECONDS", 120)
    )
    session_ttl_seconds: int = field(default_factory=lambda: _positive_int("SESSION_TTL_SECONDS", 900))
    port: int = field(default_factory=lambda: _positive_int("PORT", 8788))
    cors_origin: str | None = field(default_factory=lambda: os.environ.get("CORS_ORIGIN") or None)
    guardian_count: int = field(default_factory=lambda: _positive_int("GUARDIAN_COUNT", 5))
