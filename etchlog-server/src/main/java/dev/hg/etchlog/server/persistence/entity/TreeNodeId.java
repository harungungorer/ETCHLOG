package dev.hg.etchlog.server.persistence.entity;

import java.io.Serializable;
import java.util.Objects;

/**
 * Composite primary key for {@link TreeNodeEntity}: {@code (level, node_index)}.
 *
 * <p>Mutable with a no-arg constructor as required by JPA's {@code @IdClass} contract (a record
 * cannot be used here because records lack the public no-arg constructor JPA needs).
 */
public class TreeNodeId implements Serializable {

    private static final long serialVersionUID = 1L;

    private int level;
    private long nodeIndex;

    public TreeNodeId() {}

    public TreeNodeId(int level, long nodeIndex) {
        this.level = level;
        this.nodeIndex = nodeIndex;
    }

    public int getLevel() {
        return level;
    }

    public long getNodeIndex() {
        return nodeIndex;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TreeNodeId other)) {
            return false;
        }
        return level == other.level && nodeIndex == other.nodeIndex;
    }

    @Override
    public int hashCode() {
        return Objects.hash(level, nodeIndex);
    }

    @Override
    public String toString() {
        return "(" + level + "," + nodeIndex + ")";
    }
}
