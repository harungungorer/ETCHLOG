-- V3 (SQLite): appender authorization. Keys stored hashed (SHA-256), never plaintext.
-- SQLite has no gen_random_uuid(); the UUID id is generated in the application layer and stored as
-- a 16-byte BLOB (Hibernate's binary fallback for UUID on dialects without a native uuid type).

CREATE TABLE api_keys (
    id          BLOB         NOT NULL PRIMARY KEY,      -- app-generated UUID (16 bytes)
    key_hash    BLOB         NOT NULL,                  -- SHA-256 hash of the API key (never plaintext)
    label       VARCHAR(128) NOT NULL,
    active      INTEGER      NOT NULL DEFAULT 1,        -- boolean: 0/1
    created_at  TEXT         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  TEXT         NULL,

    CONSTRAINT uq_api_keys_hash UNIQUE (key_hash)
);
