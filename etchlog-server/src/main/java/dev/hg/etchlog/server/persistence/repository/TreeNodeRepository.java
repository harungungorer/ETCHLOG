package dev.hg.etchlog.server.persistence.repository;

import dev.hg.etchlog.server.persistence.entity.TreeNodeEntity;
import dev.hg.etchlog.server.persistence.entity.TreeNodeId;
import java.util.List;
import java.util.Optional;
import org.springframework.data.repository.Repository;

/**
 * Append-only access to the materialized {@code tree_nodes} table.
 *
 * <p>Like {@link LeafRepository}, extends the bare {@link Repository} marker so no delete/update
 * path is exposed. Inclusion-proof generation fetches sibling nodes by their {@code (level,
 * node_index)} address — exactly the primary key — so each audit-path step is an indexed point
 * lookup.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
public interface TreeNodeRepository extends Repository<TreeNodeEntity, TreeNodeId> {

    TreeNodeEntity save(TreeNodeEntity node);

    <S extends TreeNodeEntity> List<S> saveAll(Iterable<S> nodes);

    Optional<TreeNodeEntity> findById(TreeNodeId id);

    Optional<TreeNodeEntity> findByLevelAndNodeIndex(int level, long nodeIndex);

    /** All nodes at one level, ordered by position — used when materializing/scanning a level. */
    List<TreeNodeEntity> findByLevelOrderByNodeIndexAsc(int level);

    long count();
}
