package dev.hg.etchlog.core.tree;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.util.List;

/**
 * RFC 6962 §2.1 Merkle Tree Hash (MTH) over an ordered list of leaf HASHES.
 *
 * <p>This is the <em>reference</em> implementation — a direct, recursive transcription of the spec.
 * The optimized {@link CachedMerkleTree} is cross-checked against it by the property-based tests
 * (invariant: cached root == reference root for every size), so an optimization can never silently
 * corrupt correctness.
 *
 * <pre>
 *   MTH({})        = SHA-256("")              (empty tree; size 0)
 *   MTH({d0})      = d0                        (a single leaf hash is the root)
 *   MTH(d[0..n))   = hashChildren( MTH(d[0..k)), MTH(d[k..n)) )
 *                    where k = largest power of two strictly less than n
 * </pre>
 */
public final class MerkleTreeHash {

    private MerkleTreeHash() {}

    /** Computes the RFC 6962 tree head over the given ordered leaf hashes. */
    public static byte[] mth(List<byte[]> leafHashes) {
        if (leafHashes == null) {
            throw new IllegalArgumentException("leafHashes must not be null");
        }
        return mth(leafHashes, 0, leafHashes.size());
    }

    private static byte[] mth(List<byte[]> leaves, int lo, int hi) {
        int n = hi - lo;
        if (n == 0) {
            return MerkleHash.emptyTreeHash(); // RFC 6962: MTH({}) = SHA-256("")
        }
        if (n == 1) {
            return leaves.get(lo); // already a leaf hash
        }
        int k = largestPowerOfTwoLessThan(n); // split point: left subtree is a full power of two
        byte[] left = mth(leaves, lo, lo + k);
        byte[] right = mth(leaves, lo + k, hi);
        return MerkleHash.hashChildren(left, right);
    }

    /** Largest power of two strictly less than {@code n} (requires {@code n >= 2}). */
    static int largestPowerOfTwoLessThan(int n) {
        // Highest set bit of (n-1) gives the largest 2^x < n.
        return Integer.highestOneBit(n - 1);
    }
}
