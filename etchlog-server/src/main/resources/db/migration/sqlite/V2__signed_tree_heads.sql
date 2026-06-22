-- V2 (SQLite): the immutable STH history. One row per append, keyed by tree_size.

CREATE TABLE signed_tree_heads (
    tree_size          INTEGER  NOT NULL PRIMARY KEY,   -- number of leaves committed
    root_hash          BLOB     NOT NULL,               -- 32-byte Merkle root over tree_size leaves
    timestamp          TEXT     NOT NULL,               -- cryptographic STH timestamp (signed), ISO-8601
    ed25519_signature  BLOB     NOT NULL,               -- 64-byte Ed25519 sig over the serialized STH
    created_at         TEXT     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ck_sth_size_pos CHECK (tree_size >= 0),
    CONSTRAINT ck_sth_root_len CHECK (length(root_hash) = 32),
    CONSTRAINT ck_sth_sig_len  CHECK (length(ed25519_signature) = 64)
);
