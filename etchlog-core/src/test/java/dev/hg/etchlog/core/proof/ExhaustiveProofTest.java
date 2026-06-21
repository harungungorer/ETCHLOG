package dev.hg.etchlog.core.proof;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.etchlog.core.CryptoTestSupport;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Exhaustive, deterministic coverage of every {@code (size, index)} and {@code (m, n)} pair up to a
 * bound. Random property tests sample the space; this nails down the boundary-heavy index
 * arithmetic (powers of two, odd sizes, m == n) that subtle off-by-one bugs hide in.
 */
class ExhaustiveProofTest {

    private static final int MAX = 130;

    @Test
    void everyInclusionProofVerifiesForEverySizeAndIndex() {
        List<byte[]> all = CryptoTestSupport.randomLeafHashes(MAX, 42L);
        for (int n = 1; n <= MAX; n++) {
            List<byte[]> leaves = all.subList(0, n);
            byte[] root = MerkleTreeHash.mth(leaves);
            for (int i = 0; i < n; i++) {
                List<byte[]> path = InclusionProof.generate(leaves, i, n);
                assertThat(InclusionVerifier.verify(leaves.get(i), i, n, path, root))
                        .as("inclusion n=%d i=%d", n, i)
                        .isTrue();
            }
        }
    }

    @Test
    void everyConsistencyProofVerifiesForEveryMandN() {
        List<byte[]> all = CryptoTestSupport.randomLeafHashes(MAX, 99L);
        for (int n = 1; n <= MAX; n++) {
            List<byte[]> leaves = new ArrayList<>(all.subList(0, n));
            byte[] newRoot = MerkleTreeHash.mth(leaves);
            for (int m = 1; m <= n; m++) {
                byte[] oldRoot = MerkleTreeHash.mth(leaves.subList(0, m));
                List<byte[]> proof = ConsistencyProof.generate(leaves, m, n);
                assertThat(ConsistencyVerifier.verify(m, n, oldRoot, newRoot, proof))
                        .as("consistency m=%d n=%d", m, n)
                        .isTrue();
            }
        }
    }

    @Test
    void consistencyRejectsAWrongOldRoot() {
        List<byte[]> leaves = CryptoTestSupport.randomLeafHashes(MAX, 7L);
        for (int n = 2; n <= MAX; n++) {
            List<byte[]> sub = leaves.subList(0, n);
            byte[] newRoot = MerkleTreeHash.mth(sub);
            for (int m = 1; m < n; m++) {
                byte[] oldRoot = MerkleTreeHash.mth(sub.subList(0, m));
                byte[] wrongOld = CryptoTestSupport.flipOneBit(oldRoot, m + n);
                List<byte[]> proof = ConsistencyProof.generate(sub, m, n);
                assertThat(ConsistencyVerifier.verify(m, n, wrongOld, newRoot, proof))
                        .as("tampered-old m=%d n=%d", m, n)
                        .isFalse();
            }
        }
    }

    @Test
    void consistencyRejectsAWrongNewRoot() {
        List<byte[]> leaves = CryptoTestSupport.randomLeafHashes(MAX, 8L);
        for (int n = 2; n <= MAX; n++) {
            List<byte[]> sub = leaves.subList(0, n);
            byte[] newRoot = MerkleTreeHash.mth(sub);
            byte[] wrongNew = CryptoTestSupport.flipOneBit(newRoot, n);
            for (int m = 1; m < n; m++) {
                byte[] oldRoot = MerkleTreeHash.mth(sub.subList(0, m));
                List<byte[]> proof = ConsistencyProof.generate(sub, m, n);
                assertThat(ConsistencyVerifier.verify(m, n, oldRoot, wrongNew, proof))
                        .as("tampered-new m=%d n=%d", m, n)
                        .isFalse();
            }
        }
    }

    @Test
    void inclusionRejectsWrongRoot() {
        List<byte[]> leaves = CryptoTestSupport.randomLeafHashes(MAX, 5L);
        for (int n = 1; n <= MAX; n++) {
            List<byte[]> sub = leaves.subList(0, n);
            byte[] root = MerkleTreeHash.mth(sub);
            byte[] wrongRoot = CryptoTestSupport.flipOneBit(root, n);
            for (int i = 0; i < n; i++) {
                List<byte[]> path = InclusionProof.generate(sub, i, n);
                assertThat(InclusionVerifier.verify(sub.get(i), i, n, path, wrongRoot))
                        .as("wrong-root n=%d i=%d", n, i)
                        .isFalse();
            }
        }
    }
}
