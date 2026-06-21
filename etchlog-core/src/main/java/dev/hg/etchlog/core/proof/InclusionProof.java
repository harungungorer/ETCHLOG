package dev.hg.etchlog.core.proof;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 6962 §2.1.1 inclusion (audit) path generation over leaf hashes.
 *
 * <p>An inclusion proof is the ordered list of <em>sibling</em> subtree hashes encountered on the
 * path from leaf {@code m} up to the root of a size-{@code n} tree. A verifier combines them with
 * the leaf hash (deciding left/right from the index at each level) to recompute the root — see
 * {@link InclusionVerifier}.
 */
public final class InclusionProof {

    private InclusionProof() {}

    /**
     * Returns the ordered sibling hashes from leaf {@code m} up to the root of a size-{@code n}
     * tree.
     */
    public static List<byte[]> generate(List<byte[]> leafHashes, long m, long n) {
        if (leafHashes == null) {
            throw new IllegalArgumentException("leafHashes must not be null");
        }
        if (n <= 0 || n > leafHashes.size()) {
            throw new IllegalArgumentException("tree size out of range: " + n);
        }
        if (m < 0 || m >= n) {
            throw new IllegalArgumentException("leaf index must be in [0, n): " + m);
        }
        return path(leafHashes, m, 0, n);
    }

    private static List<byte[]> path(List<byte[]> leaves, long m, long lo, long hi) {
        long n = hi - lo;
        if (n == 1) {
            return new ArrayList<>(); // reached the leaf: no more siblings
        }
        long k = largestPowerOfTwoLessThan(n); // left subtree size
        List<byte[]> result;
        if (m - lo < k) {
            // Target is in the LEFT subtree: sibling is the RIGHT subtree root.
            result = path(leaves, m, lo, lo + k);
            result.add(subtreeRoot(leaves, lo + k, hi));
        } else {
            // Target is in the RIGHT subtree: sibling is the LEFT subtree root.
            result = path(leaves, m, lo + k, hi);
            result.add(subtreeRoot(leaves, lo, lo + k));
        }
        return result;
    }

    private static byte[] subtreeRoot(List<byte[]> leaves, long lo, long hi) {
        if (hi - lo == 1) {
            return leaves.get((int) lo);
        }
        long k = largestPowerOfTwoLessThan(hi - lo);
        return MerkleHash.hashChildren(
                subtreeRoot(leaves, lo, lo + k), subtreeRoot(leaves, lo + k, hi));
    }

    static long largestPowerOfTwoLessThan(long n) {
        return Long.highestOneBit(n - 1);
    }
}
