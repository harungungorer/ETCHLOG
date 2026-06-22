-- V4 (PostgreSQL): indexes for efficient audit-path / proof generation.
--
-- Audit-path sibling lookups hit the tree_nodes primary key (level, node_index) directly, so no
-- extra index is needed for the hot path. These indexes serve by-hash entry retrieval, range scans
-- while materializing a level, and the latest/previous STH queries.

-- get-entry by hash (the leaf_hash UNIQUE constraint already backs this; this index makes the
-- intent explicit and helps planners that prefer a dedicated lookup index).
CREATE INDEX idx_leaves_leaf_hash ON leaves (leaf_hash);

-- Covering helper for range scans when materializing a level during STH recomputation.
-- INCLUDE (node_hash) is a PostgreSQL covering index; SQLite ignores INCLUDE (plain index).
CREATE INDEX idx_tree_nodes_level ON tree_nodes (level, node_index) INCLUDE (node_hash);

-- Latest STH (get-signed-tree-head) and "previous STH" for monitors.
CREATE INDEX idx_sth_size_desc ON signed_tree_heads (tree_size DESC);
