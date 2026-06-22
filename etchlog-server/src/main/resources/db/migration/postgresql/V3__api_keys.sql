-- V3 (PostgreSQL): appender authorization. Reads/proofs are public, so only writes need keys.
-- Keys are stored hashed (SHA-256), never plaintext. Rotation/revocation toggles active/revoked_at.
-- The id default uses gen_random_uuid() (built into PostgreSQL 13+); the application also supplies
-- the UUID so the same write path works against SQLite, which has no gen_random_uuid().

CREATE TABLE api_keys (
    id          UUID         NOT NULL DEFAULT gen_random_uuid(),
    key_hash    BYTEA        NOT NULL,                  -- SHA-256 hash of the API key (never plaintext)
    label       VARCHAR(128) NOT NULL,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ  NULL,

    CONSTRAINT pk_api_keys      PRIMARY KEY (id),
    CONSTRAINT uq_api_keys_hash UNIQUE (key_hash)
);
