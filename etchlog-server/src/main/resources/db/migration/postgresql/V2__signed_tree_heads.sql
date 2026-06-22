-- V2 (PostgreSQL): the immutable STH history. One row per append, keyed by tree_size.
-- Keeping every STH (not just the latest) lets the log serve a consistency proof between
-- any two historical sizes a monitor previously observed.

CREATE TABLE signed_tree_heads (
    tree_size          BIGINT       NOT NULL,           -- number of leaves committed
    root_hash          BYTEA        NOT NULL,           -- 32-byte Merkle root over tree_size leaves
    timestamp          BIGINT       NOT NULL,           -- cryptographic STH timestamp (signed), epoch ms
    ed25519_signature  BYTEA        NOT NULL,           -- 64-byte Ed25519 sig over the serialized STH
    created_at         BIGINT       NOT NULL DEFAULT (EXTRACT(EPOCH FROM now()) * 1000)::BIGINT, -- epoch ms

    CONSTRAINT pk_sth          PRIMARY KEY (tree_size),
    CONSTRAINT ck_sth_size_pos CHECK (tree_size >= 0),
    CONSTRAINT ck_sth_root_len CHECK (octet_length(root_hash) = 32),
    CONSTRAINT ck_sth_sig_len  CHECK (octet_length(ed25519_signature) = 64)
);
