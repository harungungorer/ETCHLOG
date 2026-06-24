-- V6 (PostgreSQL): DB-level length backstop for api_keys.key_hash.
--
-- key_hash holds a SHA-256 digest, always 32 bytes. The application enforces this in the
-- ApiKeyEntity constructor, but the other hash/signature columns (leaf_hash, node_hash, root_hash,
-- ed25519_signature) all carry an octet_length CHECK; this adds the matching backstop for api_keys
-- so a malformed hash can never be persisted via any path.
ALTER TABLE api_keys
    ADD CONSTRAINT ck_api_keys_hash_len CHECK (octet_length(key_hash) = 32);
