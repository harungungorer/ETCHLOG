package dev.hg.etchlog.server.persistence.repository;

import dev.hg.etchlog.server.persistence.entity.ApiKeyEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.repository.Repository;

/**
 * Access to the {@code api_keys} table.
 *
 * <p>Unlike the log tables this row is mutable — rotation/revocation toggles {@code active}/{@code
 * revoked_at} via {@code save} (merge). Lookups are by the stored {@code SHA-256} key hash; the
 * caller is responsible for constant-time comparison of the candidate hash where relevant.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
public interface ApiKeyRepository extends Repository<ApiKeyEntity, UUID> {

    ApiKeyEntity save(ApiKeyEntity apiKey);

    Optional<ApiKeyEntity> findById(UUID id);

    Optional<ApiKeyEntity> findByKeyHash(byte[] keyHash);

    Optional<ApiKeyEntity> findByKeyHashAndActiveTrue(byte[] keyHash);

    List<ApiKeyEntity> findAll();

    long count();
}
