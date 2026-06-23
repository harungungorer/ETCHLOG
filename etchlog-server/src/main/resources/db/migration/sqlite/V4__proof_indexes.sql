-- V4 (SQLite): indexes for efficient audit-path / proof generation.
--
-- No tree_nodes index is added: the (level, node_index) PRIMARY KEY is itself a B-tree index that
-- already serves both the point sibling lookups and the level range scans during proof generation.
-- On SQLite a separate (level, node_index) index would exactly duplicate the PK with no covering
-- benefit (SQLite has no INCLUDE clause), so it is intentionally omitted. By-hash lookups use the
-- auto-index SQLite creates for the leaves.leaf_hash UNIQUE constraint, so no leaf_hash index either.

-- Latest STH (get-signed-tree-head) and "previous STH" for monitors.
CREATE INDEX idx_sth_size_desc ON signed_tree_heads (tree_size DESC);
