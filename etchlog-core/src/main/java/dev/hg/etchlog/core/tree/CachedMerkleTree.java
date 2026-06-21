package dev.hg.etchlog.core.tree;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.util.ArrayList;
import java.util.List;

/**
 * Optimized RFC 6962 Merkle tree over a fixed list of leaf hashes.
 *
 * <p>Where {@link MerkleTreeHash} recurses top-down splitting at the largest power of two, this
 * builds the tree <em>bottom-up</em>: at each level, adjacent nodes are paired left-to-right and a
 * trailing odd node is promoted unchanged to the next level. This iterative fold provably
 * reproduces RFC 6962's left-balanced tree head while caching every interior level, so audit paths
 * and incremental growth can reuse subtree roots.
 *
 * <p>The two implementations use different algorithms on purpose: the property-based test suite
 * asserts {@code CachedMerkleTree.of(x).root()} equals {@code MerkleTreeHash.mth(x)} for every
 * size, so any divergence is caught immediately.
 */
public final class CachedMerkleTree {

    /** levels.get(0) = leaf hashes; levels.get(top) = single-element list holding the root. */
    private final List<List<byte[]>> levels;

    private CachedMerkleTree(List<List<byte[]>> levels) {
        this.levels = levels;
    }

    /** Builds the cached tree from an ordered, defensively-copied list of leaf hashes. */
    public static CachedMerkleTree of(List<byte[]> leafHashes) {
        if (leafHashes == null) {
            throw new IllegalArgumentException("leafHashes must not be null");
        }
        List<List<byte[]>> levels = new ArrayList<>();
        List<byte[]> level0 = new ArrayList<>(leafHashes.size());
        for (byte[] h : leafHashes) {
            level0.add(h.clone());
        }
        levels.add(level0);

        if (level0.isEmpty()) {
            // Empty tree: head is SHA-256(""), kept as a degenerate top level.
            List<byte[]> top = new ArrayList<>(1);
            top.add(MerkleHash.hashLeaf(new byte[0]));
            levels.add(top);
            return new CachedMerkleTree(levels);
        }

        List<byte[]> current = level0;
        while (current.size() > 1) {
            int size = current.size();
            List<byte[]> next = new ArrayList<>((size + 1) / 2);
            int i = 0;
            for (; i + 1 < size; i += 2) {
                next.add(MerkleHash.hashChildren(current.get(i), current.get(i + 1)));
            }
            if (i < size) {
                // Trailing odd node: promote unchanged (left-balanced carry).
                next.add(current.get(i));
            }
            levels.add(next);
            current = next;
        }
        return new CachedMerkleTree(levels);
    }

    /** Number of leaves in the tree. */
    public int size() {
        return levels.get(0).size();
    }

    /** The RFC 6962 tree head (root hash) over all leaves. */
    public byte[] root() {
        return levels.get(levels.size() - 1).get(0).clone();
    }
}
