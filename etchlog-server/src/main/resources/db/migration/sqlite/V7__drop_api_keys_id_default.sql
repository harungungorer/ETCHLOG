-- V7 (SQLite): intentionally a no-op, kept for version parity with the PostgreSQL migrations.
--
-- The PostgreSQL V7 drops the gen_random_uuid() default on api_keys.id. SQLite never had that
-- default in the first place: its V3 declares `id TEXT NOT NULL PRIMARY KEY` with no DEFAULT, and
-- the application always supplies the UUID (UUID.randomUUID() in ApiKeyEntity). There is nothing to
-- drop here, so this script applies no statements — it exists only so the two vendors stay on the
-- same Flyway version number (as V5 already does, with vendor-specific content).
SELECT 1; -- no-op; keeps the migration non-empty across SQLite/JDBC drivers
