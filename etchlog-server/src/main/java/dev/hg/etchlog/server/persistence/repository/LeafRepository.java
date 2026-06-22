package dev.hg.etchlog.server.persistence.repository;

import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;

/**
 * Append-only access to the {@code leaves} table.
 *
 * <p>Extends the bare {@link Repository} marker rather than {@code CrudRepository}/{@code
 * JpaRepository} so that no {@code delete}/{@code deleteAll} method is ever exposed to application
 * code — only {@code INSERT} (via {@link #save}) and {@code SELECT} are reachable. This is the
 * app-code half of the storage-layer append-only invariant; the other half is the production DB
 * role lacking {@code UPDATE}/{@code DELETE} grants.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
public interface LeafRepository extends Repository<LeafEntity, Long> {

    LeafEntity save(LeafEntity leaf);

    Optional<LeafEntity> findById(Long leafIndex);

    /** get-entry by hash: backed by the {@code UNIQUE (leaf_hash)} constraint. */
    Optional<LeafEntity> findByLeafHash(byte[] leafHash);

    boolean existsByLeafHash(byte[] leafHash);

    long count();

    /**
     * The next leaf index the sequencer will assign (= current tree size). Correct and gap-free
     * only because the single-writer sequencer serializes appends within one transaction.
     */
    @Query("SELECT COALESCE(MAX(l.leafIndex) + 1, 0) FROM LeafEntity l")
    long nextLeafIndex();
}
