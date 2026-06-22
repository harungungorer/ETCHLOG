-- Etchlog schema, SQLite dialect (single-binary / demo profile).
-- V1: append-only record store (leaves) and the materialized Merkle tree (tree_nodes).
--
-- Deltas vs PostgreSQL: BYTEA -> BLOB, TIMESTAMPTZ -> TEXT (ISO-8601), octet_length() -> length(),
-- server now() -> CURRENT_TIMESTAMP. The logical schema is identical. Migrations only add structure.

CREATE TABLE leaves (
    leaf_index   INTEGER  NOT NULL PRIMARY KEY,         -- app-assigned append order, 0-based (no AUTOINCREMENT)
    leaf_hash    BLOB     NOT NULL,                     -- RFC 6962: SHA-256(0x00 || payload), 32 bytes
    payload      BLOB     NULL,                         -- raw record, or NULL if only a hash was submitted
    payload_size INTEGER  NOT NULL DEFAULT 0,
    created_at   TEXT     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_leaves_leaf_hash    UNIQUE (leaf_hash),
    CONSTRAINT ck_leaves_index_nonneg CHECK (leaf_index >= 0),
    CONSTRAINT ck_leaves_hash_len     CHECK (length(leaf_hash) = 32)
);

CREATE TABLE tree_nodes (
    level       INTEGER  NOT NULL,                      -- 0 = leaf hashes, 1 = parents, ...
    node_index  INTEGER  NOT NULL,                      -- 0-based index within the level
    node_hash   BLOB     NOT NULL,                      -- 32-byte RFC 6962 node hash
    created_at  TEXT     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_tree_nodes          PRIMARY KEY (level, node_index),
    CONSTRAINT ck_tree_nodes_level    CHECK (level >= 0),
    CONSTRAINT ck_tree_nodes_index    CHECK (node_index >= 0),
    CONSTRAINT ck_tree_nodes_hash_len CHECK (length(node_hash) = 32)
);
