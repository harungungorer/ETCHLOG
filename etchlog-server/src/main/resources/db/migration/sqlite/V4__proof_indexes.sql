-- V4 (SQLite): indexes for efficient audit-path / proof generation.
-- SQLite has no covering-index INCLUDE clause, so idx_tree_nodes_level is a plain composite index.
-- Audit-path sibling lookups already hit the tree_nodes primary key (level, node_index) directly,
-- and by-hash lookups use the auto-index SQLite creates for the leaves.leaf_hash UNIQUE constraint,
-- so no dedicated leaf_hash index is added.

CREATE INDEX idx_tree_nodes_level ON tree_nodes (level, node_index);

CREATE INDEX idx_sth_size_desc ON signed_tree_heads (tree_size DESC);
