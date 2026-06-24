package dev.hg.etchlog.server.persistence.repository;

import dev.hg.etchlog.server.persistence.entity.ApiKeyEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.repository.Repository;

/**
 * Access to the {@code api_keys} table.
 *
 * <p>Unlike the log tables this row is mutable — rotation/revocation toggles {@code active}/{@code
 * revoked_at} via {@code save} (merge). Lookups hash the presented key to its {@code SHA-256}
 * digest and match on the indexed {@code key_hash} column, so authentication is a single indexed
 * equality lookup on a fixed-width digest — not a character-by-character secret comparison. There
 * is no timing oracle to defend against here, so callers do <em>not</em> need a separate
 * constant-time compare: an attacker cannot steer the lookup toward a target hash without already
 * knowing the 256-bit preimage.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
public interface ApiKeyRepository extends Repository<ApiKeyEntity, UUID> {

    ApiKeyEntity save(ApiKeyEntity apiKey);

    Optional<ApiKeyEntity> findById(UUID id);

    Optional<ApiKeyEntity> findByKeyHash(byte[] keyHash);

    Optional<ApiKeyEntity> findByKeyHashAndActiveTrue(byte[] keyHash);

    long count();
}
