-- V3 (SQLite): appender authorization. Keys stored hashed (SHA-256), never plaintext.
-- SQLite has no gen_random_uuid(); the UUID id is generated in the application layer. The community
-- SQLiteDialect maps java.util.UUID to its 36-char canonical text form, so the column is TEXT (not
-- BLOB) to match what Hibernate actually stores and reads back.

CREATE TABLE api_keys (
    id          TEXT         NOT NULL PRIMARY KEY,      -- app-generated UUID (36-char canonical text)
    key_hash    BLOB         NOT NULL,                  -- SHA-256 hash of the API key (never plaintext)
    label       VARCHAR(128) NOT NULL,
    active      INTEGER      NOT NULL DEFAULT 1,        -- boolean: 0/1
    created_at  INTEGER      NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)), -- epoch ms
    revoked_at  INTEGER      NULL,                       -- epoch ms; NULL until revoked

    CONSTRAINT uq_api_keys_hash UNIQUE (key_hash)
);
