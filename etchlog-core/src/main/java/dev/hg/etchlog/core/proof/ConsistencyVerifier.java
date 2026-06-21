package dev.hg.etchlog.core.proof;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * Standalone RFC 6962 §2.1.2 consistency-proof verification.
 *
 * <p>Reconstructs <em>both</em> the size-{@code m} root and the size-{@code n} root from the proof
 * nodes and checks each against its signed counterpart. If either reconstruction fails, the
 * size-{@code m} log was <em>not</em> an unmodified prefix of the size-{@code n} log — history was
 * rewritten, reordered, or truncated — and the proof is rejected.
 *
 * <p>This is the canonical RFC 6962 / Trillian iterative algorithm. The property-based test suite
 * cross-checks it against {@link ConsistencyProof} round-trips and an independent brute-force
 * oracle for every {@code (m, n)} with {@code m <= n}.
 */
public final class ConsistencyVerifier {

    private ConsistencyVerifier() {}

    public static boolean verify(
            long m, long n, byte[] oldRoot, byte[] newRoot, List<byte[]> proof) {
        if (oldRoot == null || newRoot == null || proof == null) {
            return false;
        }
        if (m <= 0 || m > n) {
            return false;
        }
        if (m == n) {
            // Degenerate: nothing appended. Proof must be empty and roots equal.
            return proof.isEmpty() && MessageDigest.isEqual(oldRoot, newRoot);
        }

        Deque<byte[]> nodes = new ArrayDeque<>(proof);

        // If m is an exact power of two it is its own left subtree => seed with oldRoot;
        // otherwise the first proof node is the seed for both reconstructions.
        boolean mIsPowerOfTwo = (m & (m - 1)) == 0;
        if (!mIsPowerOfTwo && nodes.isEmpty()) {
            return false; // malformed: a non-power-of-two m needs a seed node
        }
        byte[] node1 = mIsPowerOfTwo ? oldRoot : nodes.pollFirst(); // rebuilds the OLD root
        byte[] node2 = node1; // rebuilds the NEW root

        long fn = m - 1;
        long sn = n - 1;
        // Shift past the part of the path shared by both subtrees (the common right spine).
        while ((fn & 1) == 1) {
            fn >>= 1;
            sn >>= 1;
        }

        for (byte[] c : nodes) {
            if (sn == 0) {
                return false; // ran out of tree before the proof was exhausted
            }
            if ((fn & 1) == 1 || fn == sn) { // right child
                if (!mIsPowerOfTwo || fn != 0) {
                    node1 = MerkleHash.hashChildren(c, node1); // contributes to OLD root
                }
                node2 = MerkleHash.hashChildren(c, node2); // contributes to NEW root
                while ((fn & 1) == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else { // left child
                node2 = MerkleHash.hashChildren(node2, c); // only the NEW root grows here
            }
            fn >>= 1;
            sn >>= 1;
        }

        // Both reconstructed roots must match their signed counterparts. A forged or
        // truncated proof cannot reproduce both signed roots without a hash collision.
        return MessageDigest.isEqual(node1, oldRoot) && MessageDigest.isEqual(node2, newRoot);
    }
}
