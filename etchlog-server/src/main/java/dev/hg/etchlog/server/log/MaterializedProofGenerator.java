package dev.hg.etchlog.server.log;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates RFC 6962 inclusion and consistency proofs by reading the <em>materialized</em>
 * perfect-subtree nodes from the store, rather than re-deriving the whole tree from level-0 leaves.
 *
 * <p>Both proof types reduce to one leaf-touching primitive: the Merkle root over a leaf range
 * {@code [lo, hi)}. The {@code path}/{@code subproof} recursions are pure index arithmetic — an
 * exact transcription of RFC 6962 §2.1.1 / §2.1.2 and of {@code etchlog-core}'s {@code
 * InclusionProof}/{@code ConsistencyProof}, which remain the authoritative spec and the oracle this
 * class is property-tested against for byte-for-byte equality.
 *
 * <p>The optimization is entirely in {@link #subtreeRoot}: when {@code [lo, hi)} is an <em>aligned,
 * complete</em> perfect subtree — {@code hi - lo} a power of two and {@code lo} a multiple of it —
 * that range is exactly the materialized node {@code (log2(len), lo / len)} and is read in one
 * lookup. Only the ephemeral right-edge ranges (incomplete subtrees, never persisted) are split and
 * recombined. Because the split always peels a complete (materialized) left subtree off and
 * recurses down the right edge, a proof reads {@code O(log N)} nodes instead of all {@code N}
 * leaves.
 *
 * <p>For proofs the requested {@code n} never exceeds the current log size, so every aligned
 * perfect subtree within {@code [0, n)} is complete and therefore materialized; {@link NodeSource}
 * is only ever asked for nodes that exist.
 */
final class MaterializedProofGenerator {

    private MaterializedProofGenerator() {}

    /**
     * Supplies the hash of the complete perfect subtree rooted at {@code (level, index)}, i.e. the
     * materialized node covering leaves {@code [index * 2^level, (index + 1) * 2^level)}. Level 0
     * is a leaf hash. Implementations must return a non-null 32-byte hash for every complete
     * subtree within the requested tree size.
     */
    @FunctionalInterface
    interface NodeSource {
        byte[] subtreeHash(int level, long index);
    }

    /**
     * RFC 6962 §2.1.1 audit path for leaf {@code m} in a tree of {@code n} leaves. Requires {@code
     * 0 <= m < n}.
     */
    static List<byte[]> inclusionPath(NodeSource source, long m, long n) {
        return path(source, m, 0, n);
    }

    private static List<byte[]> path(NodeSource source, long m, long lo, long hi) {
        long n = hi - lo;
        if (n == 1) {
            return new ArrayList<>(); // reached the leaf: no more siblings
        }
        long k = largestPowerOfTwoLessThan(n);
        List<byte[]> result;
        if (m - lo < k) {
            // Target in the LEFT subtree: sibling is the RIGHT subtree root.
            result = path(source, m, lo, lo + k);
            result.add(subtreeRoot(source, lo + k, hi));
        } else {
            // Target in the RIGHT subtree: sibling is the LEFT subtree root.
            result = path(source, m, lo + k, hi);
            result.add(subtreeRoot(source, lo, lo + k));
        }
        return result;
    }

    /**
     * RFC 6962 §2.1.2 consistency proof between sizes {@code m} and {@code n}. Requires {@code 0 <
     * m <= n}; returns an empty proof when {@code m == n}.
     */
    static List<byte[]> consistencyProof(NodeSource source, long m, long n) {
        if (m == n) {
            return new ArrayList<>(); // identical trees: empty proof
        }
        return subproof(source, m, 0, n, true);
    }

    private static List<byte[]> subproof(NodeSource source, long m, long lo, long hi, boolean b) {
        long n = hi - lo;
        if (m == n) {
            List<byte[]> result = new ArrayList<>();
            if (!b) {
                // The size-m tree is a complete subtree of the size-n tree: emit its root.
                result.add(subtreeRoot(source, lo, hi));
            }
            return result;
        }
        long k = largestPowerOfTwoLessThan(n);
        List<byte[]> result;
        if (m <= k) {
            // First tree is entirely within the left subtree.
            result = subproof(source, m, lo, lo + k, b);
            result.add(subtreeRoot(source, lo + k, hi)); // right subtree root
        } else {
            // First tree spans the whole left subtree plus part of the right.
            result = subproof(source, m - k, lo + k, hi, false);
            result.add(subtreeRoot(source, lo, lo + k)); // left subtree root
        }
        return result;
    }

    /**
     * Merkle root over leaves {@code [lo, hi)}. Returns a materialized node directly when the range
     * is an aligned complete perfect subtree; otherwise splits at the largest power of two and
     * recombines, recursing only down the (ephemeral) right edge.
     */
    private static byte[] subtreeRoot(NodeSource source, long lo, long hi) {
        long len = hi - lo;
        if (isPowerOfTwo(len) && (lo & (len - 1)) == 0L) {
            int level = Long.numberOfTrailingZeros(len);
            return source.subtreeHash(level, lo >> level);
        }
        long k = largestPowerOfTwoLessThan(len);
        return MerkleHash.hashChildren(
                subtreeRoot(source, lo, lo + k), subtreeRoot(source, lo + k, hi));
    }

    private static boolean isPowerOfTwo(long n) {
        return n > 0 && (n & (n - 1)) == 0L;
    }

    static long largestPowerOfTwoLessThan(long n) {
        return Long.highestOneBit(n - 1);
    }
}
