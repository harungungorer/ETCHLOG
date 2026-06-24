-- V6 (SQLite): DB-level length backstop for api_keys.key_hash.
--
-- SQLite cannot ALTER TABLE ... ADD CONSTRAINT, so the CHECK is introduced via the standard
-- create-copy-drop-rename table rebuild. api_keys is not referenced by any foreign key, so no
-- PRAGMA foreign_keys dance is needed; Flyway runs this migration in a transaction.
--
-- The rebuilt table is byte-for-byte the V3 definition plus ck_api_keys_hash_len, matching the
-- length(key_hash) = 32 backstop the leaf/node hash columns already carry.
CREATE TABLE api_keys_new (
    id          TEXT         NOT NULL PRIMARY KEY,      -- app-generated UUID (36-char canonical text)
    key_hash    BLOB         NOT NULL,                  -- SHA-256 hash of the API key (never plaintext)
    label       VARCHAR(128) NOT NULL,
    active      INTEGER      NOT NULL DEFAULT 1,        -- boolean: 0/1
    created_at  INTEGER      NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)), -- epoch ms
    revoked_at  INTEGER      NULL,                       -- epoch ms; NULL until revoked

    CONSTRAINT uq_api_keys_hash     UNIQUE (key_hash),
    CONSTRAINT ck_api_keys_hash_len CHECK (length(key_hash) = 32)
);

INSERT INTO api_keys_new (id, key_hash, label, active, created_at, revoked_at)
    SELECT id, key_hash, label, active, created_at, revoked_at FROM api_keys;

DROP TABLE api_keys;

ALTER TABLE api_keys_new RENAME TO api_keys;
