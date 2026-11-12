"""HTTP layer. Same routes and wire shapes as the original Node backend, plus
the guardian share mailboxes required by the randomised distribution design."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from eth_utils import keccak

from .auth import AuthService
from .config import Settings
from .db import Database
from .errors import ContractRevert, HttpError
from .guardians import GuardianService, transport_public_of
from .quota import RelayQuota
from .types import (
    ChallengeRequest,
    DepositRequest,
    RecoveryAction,
    RecoveryInitiate,
    RegisterPrepare,
    RegisterRequest,
    ShareRequest,
    VerifyRequest,
)


def hash_did(did: str) -> str:
    return "0x" + keccak(did.lower().encode()).hex()


def build_app(adapter, db: Database, guardians: GuardianService, settings: Settings) -> FastAPI:
    app = FastAPI(title="SSS DID API", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.cors_origin] if settings.cors_origin else ["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    quota = RelayQuota(db, settings.relay_quota_per_hour)

    def client_ip(request: Request) -> str:
        forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    auth = AuthService(
        adapter=adapter,
        db=db,
        apps=settings.apps,
        chain_id=adapter.chain_id,
        registry_address=adapter.registry_address,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
        session_ttl_seconds=settings.session_ttl_seconds,
    )

    @app.exception_handler(HttpError)
    async def http_error(_request: Request, error: HttpError) -> JSONResponse:
        return JSONResponse(status_code=error.status, content={"error": error.message, "code": error.code})

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, error: RequestValidationError) -> JSONResponse:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'][1:]) or 'body'}: {item['msg']}"
            for item in error.errors()
        )
        return JSONResponse(status_code=400, content={"error": detail, "code": "validation"})

    @app.exception_handler(ContractRevert)
    async def contract_revert(_request: Request, error: ContractRevert) -> JSONResponse:
        return JSONResponse(status_code=400, content={"error": str(error), "code": "contract_rejected"})

    @app.exception_handler(RuntimeError)
    async def runtime_error(_request: Request, error: RuntimeError) -> JSONResponse:
        return JSONResponse(status_code=500, content={"error": str(error), "code": "internal"})

    def resolve(did: str) -> tuple[str, dict, dict | None]:
        did_hash = hash_did(did)
        document = adapter.get_document(did_hash)
        if document is None:
            raise HttpError(404, "DID is not registered", "not_registered")
        return did_hash, document, adapter.get_recovery(did_hash)

    # ------------------------------------------------------------- health
    @app.get("/api/health")
    def health() -> dict:
        return {
            "ok": True,
            "chainId": adapter.chain_id,
            "registry": adapter.registry_address,
            "relayer": adapter.relayer_address,
            "recoveryDelay": adapter.recovery_delay,
            "apps": settings.apps,
            "challengeTtlSeconds": settings.challenge_ttl_seconds,
            "sessionTtlSeconds": settings.session_ttl_seconds,
        }

    # ---------------------------------------------------------- guardians
    @app.get("/api/guardians")
    def list_guardians() -> dict:
        return {"guardians": guardians.list_public()}

    @app.get("/api/shares/{did}")
    def share_status(did: str) -> dict:
        did_hash, _document, _recovery = resolve(did)
        return {"did": did, **guardians.status(did_hash)}

    @app.post("/api/shares/deposit", status_code=201)
    def deposit_shares(body: DepositRequest) -> dict:
        did_hash, document, _recovery = resolve(body.did)
        if document["shareRoot"].lower() != body.shareRoot.lower():
            raise HttpError(400, "shareRoot does not match the registered document", "root_mismatch")
        result = guardians.deposit(
            did_hash,
            document["shareRoot"],
            [item.model_dump() for item in body.envelopes],
            document["shareCount"],
        )
        return {"did": body.did, **result}

    @app.post("/api/recovery/shares")
    def request_shares(body: ShareRequest) -> dict:
        did_hash, document, recovery = resolve(body.did)
        if recovery is not None and not recovery["executed"] and not recovery["cancelled"]:
            threshold = recovery["threshold"]
        else:
            threshold = document["threshold"]
        return guardians.collect(
            did_hash,
            transport_public_of(body.transportPublicKey),
            body.count,
            threshold,
        )

    # ---------------------------------------------------------- identity
    @app.post("/api/identity/prepare")
    def prepare_register(body: RegisterPrepare) -> dict:
        if body.didHash.lower() != hash_did(body.did):
            raise HttpError(400, "didHash does not match did", "did_mismatch")
        if adapter.get_document(body.didHash) is not None:
            raise HttpError(409, "DID is already registered", "already_registered")
        digest = adapter.register_digest(body.model_dump())
        return {"digest": digest}

    @app.post("/api/identity/register", status_code=201)
    def register(body: RegisterRequest, request: Request) -> dict:
        quota.consume(client_ip(request))
        if body.didHash.lower() != hash_did(body.did):
            raise HttpError(400, "didHash does not match did", "did_mismatch")
        if adapter.get_document(body.didHash) is not None:
            raise HttpError(409, "DID is already registered", "already_registered")
        with db.relay_lock(body.didHash):
            result = adapter.register(body.model_dump(), body.signature)
        return {"did": body.did, "didHash": body.didHash, **result}

    @app.get("/api/did/{did}")
    def get_did(did: str) -> dict:
        did_hash, document, recovery = resolve(did)
        return {
            "did": did,
            "didHash": did_hash,
            "document": document,
            "recovery": recovery,
            "chainId": adapter.chain_id,
            "registry": adapter.registry_address,
            "recoveryDelay": adapter.recovery_delay,
        }

    @app.get("/api/audit/{did}")
    def audit(did: str) -> dict:
        did_hash, _document, _recovery = resolve(did)
        return {"did": did, "didHash": did_hash, "events": adapter.get_audit(did_hash)}

    # -------------------------------------------------------------- auth
    @app.post("/api/auth/challenge")
    def challenge(body: ChallengeRequest) -> dict:
        return auth.create_challenge(body.did, hash_did(body.did), body.appId)

    @app.post("/api/auth/verify")
    def verify(body: VerifyRequest) -> dict:
        return auth.verify(body.challengeId, body.signature)

    @app.get("/api/auth/session")
    def session(request: Request) -> dict:
        token = _bearer(request)
        current = auth.session(token)
        document = auth.require_document(hash_did(current["did"]))
        return {"session": current, "document": document}

    @app.post("/api/auth/logout")
    def logout(request: Request) -> dict:
        auth.logout(_bearer(request))
        return {"ok": True}

    # ---------------------------------------------------------- recovery
    @app.post("/api/recovery/initiate", status_code=201)
    def initiate_recovery(body: RecoveryInitiate, request: Request) -> dict:
        quota.consume(client_ip(request))
        did_hash, document, recovery = resolve(body.did)
        if not document["active"]:
            raise HttpError(409, "identity is not active", "inactive")
        if body.newAuthKey.lower() == document["authKey"].lower():
            raise HttpError(400, "new auth key must differ from the current one", "same_key")
        if recovery is not None and not recovery["executed"] and not recovery["cancelled"]:
            raise HttpError(409, "a recovery request is already pending", "recovery_pending")
        with db.relay_lock(did_hash):
            return adapter.initiate_recovery({**body.model_dump(), "didHash": did_hash})

    @app.post("/api/recovery/prepare")
    def prepare_recovery(body: dict) -> dict:
        did = body.get("did")
        if not isinstance(did, str):
            raise HttpError(400, "did: field required", "validation")
        _did_hash, document, recovery = resolve(did)
        if recovery is None or recovery["executed"] or recovery["cancelled"]:
            raise HttpError(404, "no pending recovery request", "no_pending")
        return {
            "did": did,
            "document": document,
            "request": recovery,
            "digest": adapter.recovery_digest(hash_did(did), recovery),
            "readyAt": recovery["executeAfter"],
        }

    @app.post("/api/recovery/execute")
    def execute_recovery(body: RecoveryAction, request: Request) -> dict:
        quota.consume(client_ip(request))
        did_hash, _document, recovery = resolve(body.did)
        if recovery is None or recovery["executed"] or recovery["cancelled"]:
            raise HttpError(404, "no pending recovery request", "no_pending")
        if recovery["requestId"] != body.requestId:
            raise HttpError(409, "requestId does not match the pending request", "stale_request")
        with db.relay_lock(did_hash):
            result = adapter.execute_recovery(did_hash, body.requestId, body.signature)
        return {**result, "document": adapter.get_document(did_hash)}

    @app.post("/api/recovery/cancel/prepare")
    def prepare_cancel(body: dict) -> dict:
        did = body.get("did")
        if not isinstance(did, str):
            raise HttpError(400, "did: field required", "validation")
        did_hash, _document, recovery = resolve(did)
        if recovery is None or recovery["executed"] or recovery["cancelled"]:
            raise HttpError(404, "no pending recovery request", "no_pending")
        return {
            "requestId": recovery["requestId"],
            "digest": adapter.cancel_digest(did_hash, recovery["requestId"]),
        }

    @app.post("/api/recovery/cancel")
    def cancel_recovery(body: RecoveryAction, request: Request) -> dict:
        quota.consume(client_ip(request))
        did_hash, _document, recovery = resolve(body.did)
        if recovery is None or recovery["executed"] or recovery["cancelled"]:
            raise HttpError(404, "no pending recovery request", "no_pending")
        with db.relay_lock(did_hash):
            return adapter.cancel_recovery(did_hash, body.requestId, body.signature)

    return app


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    return header[7:] if header.startswith("Bearer ") else None
