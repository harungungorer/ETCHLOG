package dev.hg.etchlog.core.proof;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.security.MessageDigest;
import java.util.List;

/**
 * Standalone RFC 6962 §2.1.1 inclusion-proof verification.
 *
 * <p>Recomputes the tree root from a leaf hash plus its audit path and compares it to the expected
 * (STH) root. Verification never sees the whole tree — only the leaf hash, its index, the tree
 * size, and the sibling path — so it can run in a CLI, a cron monitor, or the browser with <em>no
 * server trust</em>.
 */
public final class InclusionVerifier {

    private InclusionVerifier() {}

    /**
     * Returns {@code true} only if the audit path reconstructs exactly {@code expectedRoot}.
     *
     * <p>The walk uses the leaf index and tree size to decide, at each level, whether the running
     * hash is the left or right child.
     */
    public static boolean verify(
            byte[] leafHash,
            long leafIndex,
            long treeSize,
            List<byte[]> auditPath,
            byte[] expectedRoot) {
        if (leafHash == null || auditPath == null || expectedRoot == null) {
            return false;
        }
        if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) {
            return false;
        }
        long fn = leafIndex; // node position within its current level
        long sn = treeSize - 1; // last index within its current level
        byte[] r = leafHash; // running hash, starts at the leaf
        for (byte[] sibling : auditPath) {
            if (sn == 0) {
                return false; // ran out of tree before the path was exhausted
            }
            if ((fn & 1) == 1 || fn == sn) { // running node is a RIGHT child
                r = MerkleHash.hashChildren(sibling, r);
                // climb to parent: drop trailing ones so fn/sn land on the next level
                while ((fn & 1) == 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else { // running node is a LEFT child
                r = MerkleHash.hashChildren(r, sibling);
            }
            fn >>= 1;
            sn >>= 1;
        }
        // Constant-time compare of the recomputed root vs the expected STH root.
        return sn == 0 && MessageDigest.isEqual(r, expectedRoot);
    }
}
