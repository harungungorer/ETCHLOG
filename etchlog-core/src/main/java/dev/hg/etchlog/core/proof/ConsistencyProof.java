package dev.hg.etchlog.core.proof;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 6962 §2.1.2 consistency proof generation between sizes {@code m <= n}.
 *
 * <p>A consistency proof is the minimal set of subtree hashes that lets a verifier reconstruct
 * <em>both</em> the size-{@code m} root and the size-{@code n} root, proving the size-{@code m} log
 * is an unmodified prefix of the size-{@code n} log. Verification lives in {@link
 * ConsistencyVerifier}.
 *
 * <p>Direct transcription of the RFC's {@code PROOF}/{@code SUBPROOF} recursion:
 *
 * <pre>
 *   PROOF(m, D[0:n]):  m == n ? {}  :  SUBPROOF(m, D[0:n], true)
 *   SUBPROOF(m, D[0:n], b):
 *     m == n           -> b ? {} : { MTH(D[0:n]) }
 *     m <= k           -> SUBPROOF(m, D[0:k], b)        ++ { MTH(D[k:n]) }
 *     m  > k           -> SUBPROOF(m-k, D[k:n], false)  ++ { MTH(D[0:k]) }
 *   where k = largest power of two strictly less than n.
 * </pre>
 */
public final class ConsistencyProof {

    private ConsistencyProof() {}

    /**
     * Returns the consistency proof nodes between sizes {@code m} and {@code n} ({@code 0 < m <=
     * n}).
     */
    public static List<byte[]> generate(List<byte[]> leafHashes, long m, long n) {
        if (leafHashes == null) {
            throw new IllegalArgumentException("leafHashes must not be null");
        }
        if (n <= 0 || n > leafHashes.size()) {
            throw new IllegalArgumentException("second tree size out of range: " + n);
        }
        if (m <= 0 || m > n) {
            throw new IllegalArgumentException("first size must be in (0, n]: " + m);
        }
        if (m == n) {
            return new ArrayList<>(); // identical trees: empty proof
        }
        return subproof(leafHashes, m, 0, n, true);
    }

    private static List<byte[]> subproof(List<byte[]> leaves, long m, long lo, long hi, boolean b) {
        long n = hi - lo;
        if (m == n) {
            List<byte[]> result = new ArrayList<>();
            if (!b) {
                // The size-m tree is a complete subtree of the size-n tree: emit its root.
                result.add(subtreeRoot(leaves, lo, hi));
            }
            return result;
        }
        long k = largestPowerOfTwoLessThan(n);
        List<byte[]> result;
        if (m <= k) {
            // First tree is entirely within the left subtree.
            result = subproof(leaves, m, lo, lo + k, b);
            result.add(subtreeRoot(leaves, lo + k, hi)); // right subtree root
        } else {
            // First tree spans the whole left subtree plus part of the right.
            result = subproof(leaves, m - k, lo + k, hi, false);
            result.add(subtreeRoot(leaves, lo, lo + k)); // left subtree root
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
