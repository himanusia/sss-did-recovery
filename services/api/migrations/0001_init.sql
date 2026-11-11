-- Off-chain state: sessions, one-shot challenges, guardian share mailboxes.
-- The chain stays the source of truth for identity documents; nothing here can
-- mint authority or hold a plaintext share.

CREATE TABLE IF NOT EXISTS guardians (
    id            text PRIMARY KEY,
    label         text NOT NULL,
    public_key    bytea NOT NULL,   -- X25519 public key (32 bytes)
    private_key   bytea NOT NULL,   -- demo guardian service, co-located; never leaves this row
    active        boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS challenges (
    id            text PRIMARY KEY,           -- 32 hex chars, single use
    did           text NOT NULL,
    did_hash      text NOT NULL,
    app_id        text NOT NULL,
    app_name      text NOT NULL,
    nonce         text NOT NULL,
    typed_data    jsonb NOT NULL,
    issued_at     bigint NOT NULL,            -- unix seconds
    expires_at    bigint NOT NULL,            -- unix seconds
    consumed      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS challenges_expiry_idx ON challenges (expires_at);

CREATE TABLE IF NOT EXISTS sessions (
    token         text PRIMARY KEY,           -- 64 hex chars, bearer secret
    did           text NOT NULL,
    app_id        text NOT NULL,
    auth_key      text NOT NULL,
    issued_at     bigint NOT NULL,            -- unix milliseconds (client contract)
    expires_at    bigint NOT NULL,            -- unix milliseconds
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS guardian_envelopes (
    did_hash      text NOT NULL,
    guardian_id   text NOT NULL REFERENCES guardians (id),
    ciphertext    bytea NOT NULL,             -- sealed box; opaque to the server
    share_root    text NOT NULL,
    deposited_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (did_hash, guardian_id)
);

CREATE TABLE IF NOT EXISTS share_requests (
    id                    bigserial PRIMARY KEY,
    did_hash              text NOT NULL,
    transport_public_key  bytea NOT NULL,
    requested_count       integer NOT NULL,
    guardians             text[] NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- Serialises relayer transactions per DID across API instances.
CREATE TABLE IF NOT EXISTS relay_locks (
    did_hash      text PRIMARY KEY,
    locked_until  timestamptz NOT NULL
);
