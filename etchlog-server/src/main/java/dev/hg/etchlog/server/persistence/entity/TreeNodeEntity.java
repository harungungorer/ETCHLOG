package dev.hg.etchlog.server.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Objects;

/**
 * A materialized Merkle node addressed by {@code (level, node_index)}.
 *
 * <p>{@code level = 0} is the leaf-hash row (its {@code node_hash} equals the corresponding {@code
 * leaves.leaf_hash}); higher levels are interior nodes. Persisting nodes lets inclusion-proof
 * generation read precomputed sibling hashes via indexed point lookups instead of recomputing
 * subtrees. Nodes are immutable once materialized — RFC 6962 hashes are deterministic, so a node at
 * a given address never changes value.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
@Entity
@Table(name = "tree_nodes")
@IdClass(TreeNodeId.class)
public class TreeNodeEntity {

    /** {@code 0} = leaf-hash level; each level up halves the node count (rounding up). */
    @Id
    @Column(name = "level", nullable = false, updatable = false)
    private int level;

    @Id
    @Column(name = "node_index", nullable = false, updatable = false)
    private long nodeIndex;

    /**
     * {@code level 0}: {@code leafHash(payload)}; {@code level > 0}: {@code nodeHash(left, right)}.
     * Exactly 32 bytes, enforced by the constructor and a DB CHECK constraint;
     * {@code @Column(length=…)} is a no-op for binary columns, so it is omitted.
     */
    @Column(name = "node_hash", nullable = false, updatable = false)
    private byte[] nodeHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /** JPA-only. */
    protected TreeNodeEntity() {}

    public TreeNodeEntity(int level, long nodeIndex, byte[] nodeHash) {
        if (level < 0) {
            throw new IllegalArgumentException("level must be >= 0");
        }
        if (nodeIndex < 0) {
            throw new IllegalArgumentException("nodeIndex must be >= 0");
        }
        if (nodeHash == null || nodeHash.length != 32) {
            throw new IllegalArgumentException("nodeHash must be exactly 32 bytes");
        }
        this.level = level;
        this.nodeIndex = nodeIndex;
        this.nodeHash = nodeHash.clone();
        this.createdAt = Instant.now();
    }

    public int getLevel() {
        return level;
    }

    public long getNodeIndex() {
        return nodeIndex;
    }

    public byte[] getNodeHash() {
        return nodeHash.clone();
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TreeNodeEntity other)) {
            return false;
        }
        return level == other.level && nodeIndex == other.nodeIndex;
    }

    @Override
    public int hashCode() {
        // Kept identical to TreeNodeId.hashCode() so the entity and its @IdClass key agree when
        // either is used as a map/set key.
        return Objects.hash(level, nodeIndex);
    }

    @Override
    public String toString() {
        return "TreeNodeEntity{level=" + level + ", nodeIndex=" + nodeIndex + '}';
    }
}
