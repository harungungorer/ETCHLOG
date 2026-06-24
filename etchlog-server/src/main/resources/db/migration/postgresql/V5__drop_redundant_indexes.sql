-- V5 (PostgreSQL): drop indexes that V4 created but which turned out to be redundant.
--
-- This is the forward-migration replacement for what was briefly (and incorrectly) done by editing
-- V4 in place. Migrations are immutable once published; corrections ship as a new version so any
-- database that already applied the original V4 converges cleanly instead of failing Flyway's
-- checksum validation on startup.
--
-- idx_leaves_leaf_hash duplicated the index PostgreSQL already creates to back the
-- leaves.leaf_hash UNIQUE constraint, so by-hash lookups never needed a second index.
DROP INDEX IF EXISTS idx_leaves_leaf_hash;
