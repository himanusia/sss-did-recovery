"""Request/response models. Field names follow the client contract (camelCase)."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator, model_validator

ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
BYTES32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
SIGNATURE = re.compile(r"^0x[0-9a-fA-F]{130}$")
DID = re.compile(r"^did:sss:0x[0-9a-fA-F]{40}$")


class SharePolicy(BaseModel):
    threshold: int = Field(ge=2, le=255)
    shareCount: int = Field(ge=2, le=255)

    @model_validator(mode="after")
    def check_policy(self):
        if self.shareCount < self.threshold:
            raise ValueError("shareCount must be >= threshold")
        return self


class RegisterPrepare(BaseModel):
    did: str
    didHash: str
    authKey: str
    recoveryKey: str
    shareRoot: str
    threshold: int = Field(ge=2, le=255)
    shareCount: int = Field(ge=2, le=255)

    _did = field_validator("did")(lambda v: _match(v, DID, "must be a did:sss identifier"))
    _did_hash = field_validator("didHash")(lambda v: _match(v, BYTES32, "must be a 32-byte hex value"))
    _auth = field_validator("authKey")(lambda v: _match(v, ADDRESS, "must be an Ethereum address"))
    _recovery = field_validator("recoveryKey")(
        lambda v: _match(v, ADDRESS, "must be an Ethereum address")
    )
    _root = field_validator("shareRoot")(lambda v: _match(v, BYTES32, "must be a 32-byte hex value"))

    @model_validator(mode="after")
    def check_policy(self):
        if self.shareCount < self.threshold:
            raise ValueError("shareCount must be >= threshold")
        return self


class RegisterRequest(RegisterPrepare):
    signature: str

    _sig = field_validator("signature")(lambda v: _match(v, SIGNATURE, "must be a 65-byte signature"))


class ChallengeRequest(BaseModel):
    did: str
    appId: str = Field(min_length=1, max_length=64)

    _did = field_validator("did")(lambda v: _match(v, DID, "must be a did:sss identifier"))


class VerifyRequest(BaseModel):
    challengeId: str = Field(min_length=32, max_length=32)
    signature: str

    _sig = field_validator("signature")(lambda v: _match(v, SIGNATURE, "must be a 65-byte signature"))


class RecoveryInitiate(BaseModel):
    did: str
    newAuthKey: str
    newRecoveryKey: str
    newShareRoot: str
    threshold: int = Field(ge=2, le=255)
    shareCount: int = Field(ge=2, le=255)

    _did = field_validator("did")(lambda v: _match(v, DID, "must be a did:sss identifier"))
    _auth = field_validator("newAuthKey")(lambda v: _match(v, ADDRESS, "must be an Ethereum address"))
    _recovery = field_validator("newRecoveryKey")(
        lambda v: _match(v, ADDRESS, "must be an Ethereum address")
    )
    _root = field_validator("newShareRoot")(
        lambda v: _match(v, BYTES32, "must be a 32-byte hex value")
    )

    @model_validator(mode="after")
    def check_policy(self):
        if self.shareCount < self.threshold:
            raise ValueError("shareCount must be >= threshold")
        return self


class RecoveryAction(BaseModel):
    did: str
    requestId: str = Field(pattern=r"^\d+$")
    signature: str

    _did = field_validator("did")(lambda v: _match(v, DID, "must be a did:sss identifier"))
    _sig = field_validator("signature")(lambda v: _match(v, SIGNATURE, "must be a 65-byte signature"))


class SealedEnvelope(BaseModel):
    guardianId: str = Field(min_length=1, max_length=64)
    ciphertext: str = Field(min_length=2)

    @field_validator("ciphertext")
    def hex_ciphertext(cls, value: str) -> str:
        if not value.startswith("0x"):
            raise ValueError("ciphertext must be 0x-prefixed hex")
        try:
            bytes.fromhex(value[2:])
        except ValueError as error:
            raise ValueError("ciphertext must be valid hex") from error
        return value


class DepositRequest(BaseModel):
    did: str
    shareRoot: str
    envelopes: list[SealedEnvelope] = Field(min_length=2, max_length=255)

    _did = field_validator("did")(lambda v: _match(v, DID, "must be a did:sss identifier"))
    _root = field_validator("shareRoot")(lambda v: _match(v, BYTES32, "must be a 32-byte hex value"))


class ShareRequest(BaseModel):
    did: str
    transportPublicKey: str
    count: int = Field(ge=2, le=255)

    _did = field_validator("did")(lambda v: _match(v, DID, "must be a did:sss identifier"))

    @field_validator("transportPublicKey")
    def hex_key(cls, value: str) -> str:
        raw = value[2:] if value.startswith("0x") else value
        if len(raw) != 64:
            raise ValueError("transportPublicKey must be a 32-byte hex value")
        bytes.fromhex(raw)
        return value


def _match(value: str, pattern: re.Pattern[str], message: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise ValueError(message)
    return value
