-- Etchlog schema, PostgreSQL dialect.
-- V1: the append-only record store (leaves) and the materialized Merkle tree (tree_nodes).
--
-- Migrations only ADD structure. Never write a migration that mutates or deletes
-- leaf/node/STH rows — that would break historical proofs. RFC 6962 hashing and the
-- STH serialization are frozen; version the API, not the math.

CREATE TABLE leaves (
    leaf_index   BIGINT       NOT NULL,                 -- position = append order, 0-based
    leaf_hash    BYTEA        NOT NULL,                 -- RFC 6962: SHA-256(0x00 || payload), 32 bytes
    payload      BYTEA        NULL,                     -- raw record, or NULL if only a hash was submitted
    payload_size INTEGER      NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT pk_leaves              PRIMARY KEY (leaf_index),
    CONSTRAINT uq_leaves_leaf_hash    UNIQUE (leaf_hash),
    CONSTRAINT ck_leaves_index_nonneg CHECK (leaf_index >= 0),
    CONSTRAINT ck_leaves_hash_len     CHECK (octet_length(leaf_hash) = 32)
);

CREATE TABLE tree_nodes (
    level       INTEGER      NOT NULL,                  -- 0 = leaf hashes, 1 = parents, ...
    node_index  BIGINT       NOT NULL,                  -- 0-based index within the level
    node_hash   BYTEA        NOT NULL,                  -- 32-byte RFC 6962 node hash
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT pk_tree_nodes          PRIMARY KEY (level, node_index),
    CONSTRAINT ck_tree_nodes_level    CHECK (level >= 0),
    CONSTRAINT ck_tree_nodes_index    CHECK (node_index >= 0),
    CONSTRAINT ck_tree_nodes_hash_len CHECK (octet_length(node_hash) = 32)
);
