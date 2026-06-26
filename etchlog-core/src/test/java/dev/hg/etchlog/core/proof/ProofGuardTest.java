package dev.hg.etchlog.core.proof;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.core.CryptoTestSupport;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Guard / edge-case coverage for the proof generators and standalone verifiers.
 *
 * <p>The property suite ({@link ProofInvariantsPropertyTest}) exhaustively exercises the happy
 * paths; this class pins the defensive branches — null/range rejection, malformed and
 * over/under-sized proofs, and the constant-time root mismatch — so a regression that silently
 * accepted a bad proof (a false security claim) fails the build.
 */
class ProofGuardTest {

    private static List<byte[]> leaves(int n) {
        return CryptoTestSupport.randomLeafHashes(n, 42L);
    }

    private static byte[] root(List<byte[]> all, int size) {
        return MerkleTreeHash.mth(all.subList(0, size));
    }

    // ---- InclusionProof.generate guards -------------------------------------------------------

    @Test
    void inclusionProofRejectsNullLeaves() {
        assertThatThrownBy(() -> InclusionProof.generate(null, 0, 1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void inclusionProofRejectsTreeSizeOutOfRange() {
        List<byte[]> leaves = leaves(4);
        assertThatThrownBy(() -> InclusionProof.generate(leaves, 0, 0)) // n <= 0
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> InclusionProof.generate(leaves, 0, 5)) // n > size
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void inclusionProofRejectsLeafIndexOutOfRange() {
        List<byte[]> leaves = leaves(4);
        assertThatThrownBy(() -> InclusionProof.generate(leaves, -1, 4)) // m < 0
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> InclusionProof.generate(leaves, 4, 4)) // m >= n
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ---- ConsistencyProof.generate guards -----------------------------------------------------

    @Test
    void consistencyProofRejectsNullLeaves() {
        assertThatThrownBy(() -> ConsistencyProof.generate(null, 1, 2))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void consistencyProofRejectsSecondSizeOutOfRange() {
        List<byte[]> leaves = leaves(4);
        assertThatThrownBy(() -> ConsistencyProof.generate(leaves, 1, 0)) // n <= 0
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ConsistencyProof.generate(leaves, 1, 5)) // n > size
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void consistencyProofRejectsFirstSizeOutOfRange() {
        List<byte[]> leaves = leaves(4);
        assertThatThrownBy(() -> ConsistencyProof.generate(leaves, 0, 4)) // m <= 0
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ConsistencyProof.generate(leaves, 5, 4)) // m > n
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void consistencyProofForEqualSizesIsEmpty() {
        List<byte[]> leaves = leaves(4);
        assertThat(ConsistencyProof.generate(leaves, 3, 3)).isEmpty();
    }

    // ---- InclusionVerifier branches -----------------------------------------------------------

    @Test
    void inclusionVerifierAcceptsLeftAndRightChildLeaves() {
        List<byte[]> leaves = leaves(5);
        byte[] root = root(leaves, 5);
        // index 0 is a left child; index 3 is a right child; index 4 is the fn == sn carry.
        for (int i : new int[] {0, 3, 4}) {
            List<byte[]> path = InclusionProof.generate(leaves, i, 5);
            assertThat(InclusionVerifier.verify(leaves.get(i), i, 5, path, root))
                    .as("leaf %d should verify", i)
                    .isTrue();
        }
    }

    @Test
    void inclusionVerifierRejectsNullArguments() {
        List<byte[]> leaves = leaves(4);
        byte[] root = root(leaves, 4);
        List<byte[]> path = InclusionProof.generate(leaves, 1, 4);
        assertThat(InclusionVerifier.verify(null, 1, 4, path, root)).isFalse();
        assertThat(InclusionVerifier.verify(leaves.get(1), 1, 4, null, root)).isFalse();
        assertThat(InclusionVerifier.verify(leaves.get(1), 1, 4, path, null)).isFalse();
    }

    @Test
    void inclusionVerifierRejectsOutOfRangeIndexAndSize() {
        List<byte[]> leaves = leaves(4);
        byte[] root = root(leaves, 4);
        List<byte[]> path = InclusionProof.generate(leaves, 1, 4);
        assertThat(InclusionVerifier.verify(leaves.get(1), -1, 4, path, root)).isFalse(); // idx < 0
        assertThat(InclusionVerifier.verify(leaves.get(1), 0, 0, path, root))
                .isFalse(); // size <= 0
        assertThat(InclusionVerifier.verify(leaves.get(1), 4, 4, path, root)).isFalse(); // idx >= n
    }

    @Test
    void inclusionVerifierRejectsWrongRoot() {
        List<byte[]> leaves = leaves(4);
        byte[] root = root(leaves, 4);
        List<byte[]> path = InclusionProof.generate(leaves, 1, 4);
        byte[] wrongRoot = CryptoTestSupport.flipOneBit(root, 7);
        assertThat(InclusionVerifier.verify(leaves.get(1), 1, 4, path, wrongRoot)).isFalse();
    }

    @Test
    void inclusionVerifierRejectsOversizedAndTruncatedPaths() {
        List<byte[]> leaves = leaves(4);
        byte[] root = root(leaves, 4);
        List<byte[]> path = InclusionProof.generate(leaves, 1, 4);

        // Oversized: an extra sibling drives the walk past the top (sn == 0 mid-loop).
        List<byte[]> oversized = new ArrayList<>(path);
        oversized.add(leaves.get(0).clone());
        assertThat(InclusionVerifier.verify(leaves.get(1), 1, 4, oversized, root)).isFalse();

        // Truncated: the walk ends before the root (final sn != 0).
        List<byte[]> truncated = new ArrayList<>(path.subList(0, path.size() - 1));
        assertThat(InclusionVerifier.verify(leaves.get(1), 1, 4, truncated, root)).isFalse();
    }

    // ---- ConsistencyVerifier branches ---------------------------------------------------------

    @Test
    void consistencyVerifierAcceptsValidProofs() {
        List<byte[]> leaves = leaves(8);
        // m = 3 (not a power of two -> seeded by the first proof node) into n = 5.
        assertConsistent(leaves, 3, 5);
        // m = 4 (a power of two -> seeded by oldRoot) into n = 8.
        assertConsistent(leaves, 4, 8);
    }

    private static void assertConsistent(List<byte[]> leaves, int m, int n) {
        List<byte[]> proof = ConsistencyProof.generate(leaves, m, n);
        assertThat(ConsistencyVerifier.verify(m, n, root(leaves, m), root(leaves, n), proof))
                .as("consistency %d -> %d", m, n)
                .isTrue();
    }

    @Test
    void consistencyVerifierRejectsNullArguments() {
        List<byte[]> leaves = leaves(5);
        byte[] oldRoot = root(leaves, 3);
        byte[] newRoot = root(leaves, 5);
        List<byte[]> proof = ConsistencyProof.generate(leaves, 3, 5);
        assertThat(ConsistencyVerifier.verify(3, 5, null, newRoot, proof)).isFalse();
        assertThat(ConsistencyVerifier.verify(3, 5, oldRoot, null, proof)).isFalse();
        assertThat(ConsistencyVerifier.verify(3, 5, oldRoot, newRoot, null)).isFalse();
    }

    @Test
    void consistencyVerifierRejectsBadFirstSize() {
        List<byte[]> leaves = leaves(5);
        byte[] oldRoot = root(leaves, 3);
        byte[] newRoot = root(leaves, 5);
        List<byte[]> proof = ConsistencyProof.generate(leaves, 3, 5);
        assertThat(ConsistencyVerifier.verify(0, 5, oldRoot, newRoot, proof)).isFalse(); // m <= 0
        assertThat(ConsistencyVerifier.verify(6, 5, oldRoot, newRoot, proof)).isFalse(); // m > n
    }

    @Test
    void consistencyVerifierHandlesEqualSizes() {
        List<byte[]> leaves = leaves(5);
        byte[] root = root(leaves, 3);
        assertThat(ConsistencyVerifier.verify(3, 3, root, root, List.of())).isTrue();
        // Non-empty proof for equal sizes is malformed.
        assertThat(ConsistencyVerifier.verify(3, 3, root, root, List.of(root))).isFalse();
        // Equal sizes but mismatched roots cannot be consistent.
        byte[] other = CryptoTestSupport.flipOneBit(root, 1);
        assertThat(ConsistencyVerifier.verify(3, 3, root, other, List.of())).isFalse();
    }

    @Test
    void consistencyVerifierRejectsMalformedNonPowerOfTwoSeed() {
        List<byte[]> leaves = leaves(5);
        // m = 3 is not a power of two, so a non-empty seed node is required.
        assertThat(ConsistencyVerifier.verify(3, 5, root(leaves, 3), root(leaves, 5), List.of()))
                .isFalse();
    }

    @Test
    void consistencyVerifierRejectsOversizedProof() {
        List<byte[]> leaves = leaves(5);
        List<byte[]> proof = new ArrayList<>(ConsistencyProof.generate(leaves, 3, 5));
        proof.add(leaves.get(0).clone()); // extra node drives the walk past the top
        assertThat(ConsistencyVerifier.verify(3, 5, root(leaves, 3), root(leaves, 5), proof))
                .isFalse();
    }

    @Test
    void consistencyVerifierRejectsTruncatedProof() {
        // Dropping the last node leaves the walk short of the root (final sn != 0), so the
        // terminal sn == 0 check rejects it structurally rather than relying on the root compare.
        // Exercise a power-of-two seed (m=4) and a non-power-of-two seed (m=3) into n=8.
        List<byte[]> leaves = leaves(8);
        for (int m : new int[] {3, 4}) {
            List<byte[]> full = ConsistencyProof.generate(leaves, m, 8);
            List<byte[]> truncated = new ArrayList<>(full.subList(0, full.size() - 1));
            assertThat(
                            ConsistencyVerifier.verify(
                                    m, 8, root(leaves, m), root(leaves, 8), truncated))
                    .as("truncated consistency proof m=%d -> 8 must be rejected", m)
                    .isFalse();
        }
    }

    @Test
    void consistencyVerifierRejectsMismatchedRoots() {
        List<byte[]> leaves = leaves(5);
        byte[] oldRoot = root(leaves, 3);
        byte[] newRoot = root(leaves, 5);
        List<byte[]> proof = ConsistencyProof.generate(leaves, 3, 5);
        assertThat(
                        ConsistencyVerifier.verify(
                                3, 5, CryptoTestSupport.flipOneBit(oldRoot, 2), newRoot, proof))
                .isFalse();
        assertThat(
                        ConsistencyVerifier.verify(
                                3, 5, oldRoot, CryptoTestSupport.flipOneBit(newRoot, 2), proof))
                .isFalse();
    }
}
