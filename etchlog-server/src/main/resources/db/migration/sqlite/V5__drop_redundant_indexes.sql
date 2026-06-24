-- V5 (SQLite): drop indexes that V4 created but which turned out to be redundant.
--
-- This is the forward-migration replacement for what was briefly (and incorrectly) done by editing
-- V4 in place. Migrations are immutable once published; corrections ship as a new version so any
-- database that already applied the original V4 (e.g. a local ./data/etchlog.db) converges cleanly
-- instead of failing Flyway's checksum validation on startup.
--
-- idx_leaves_leaf_hash duplicated the auto-index SQLite creates for the leaves.leaf_hash UNIQUE
-- constraint. idx_tree_nodes_level exactly duplicated the (level, node_index) PRIMARY KEY B-tree
-- (SQLite has no INCLUDE clause, so there is no covering benefit). Both are redundant.
DROP INDEX IF EXISTS idx_leaves_leaf_hash;
DROP INDEX IF EXISTS idx_tree_nodes_level;
