package dev.hg.etchlog.server.persistence.repository;

import dev.hg.etchlog.server.persistence.entity.SignedTreeHeadEntity;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.repository.Repository;

/**
 * Append-only access to the immutable {@code signed_tree_heads} history.
 *
 * <p>Each append inserts a new STH keyed by {@code tree_size}; old rows are never updated or
 * deleted, so the bare {@link Repository} marker (insert/select only) is exactly the right surface.
 * Monitors read the latest STH and fetch historical STHs to bracket a consistency proof.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
public interface SignedTreeHeadRepository extends Repository<SignedTreeHeadEntity, Long> {

    SignedTreeHeadEntity save(SignedTreeHeadEntity sth);

    Optional<SignedTreeHeadEntity> findById(Long treeSize);

    /** get-signed-tree-head: the current head, backed by {@code idx_sth_size_desc}. */
    Optional<SignedTreeHeadEntity> findFirstByOrderByTreeSizeDesc();

    /** Fetch specific historical STHs to bracket a consistency proof between observed sizes. */
    List<SignedTreeHeadEntity> findByTreeSizeIn(Collection<Long> treeSizes);

    long count();
}
