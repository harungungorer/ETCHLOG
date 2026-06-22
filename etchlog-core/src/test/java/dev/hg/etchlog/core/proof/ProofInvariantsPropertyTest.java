package dev.hg.etchlog.core.proof;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.etchlog.core.CryptoTestSupport;
import dev.hg.etchlog.core.tree.CachedMerkleTree;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import java.util.List;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.LongRange;

/**
 * The project's correctness contract, asserted over randomly generated logs and queries.
 *
 * <p>A subtly-wrong proof is worse than no proof, so these invariants are first-class deliverables
 * — any change to proof/hashing code that breaks them must fail CI.
 */
class ProofInvariantsPropertyTest {

    /** INVARIANT 1: for any log of size N and any i &lt; N, the inclusion proof verifies. */
    @Property(tries = 1000)
    void anyInclusionProofVerifies(
            @ForAll @IntRange(min = 1, max = 512) int n,
            @ForAll @IntRange(min = 0, max = Integer.MAX_VALUE) int rawI) {
        int i = rawI % n;
        List<byte[]> leaves = CryptoTestSupport.randomLeafHashes(n, 31L * n + i);
        byte[] root = MerkleTreeHash.mth(leaves);
        List<byte[]> path = InclusionProof.generate(leaves, i, n);
        assertThat(InclusionVerifier.verify(leaves.get(i), i, n, path, root)).isTrue();
    }

    /** INVARIANT 2: any consistency proof between sizes M &le; N verifies. */
    @Property(tries = 1000)
    void anyConsistencyProofVerifies(
            @ForAll @IntRange(min = 1, max = 512) int n,
            @ForAll @IntRange(min = 1, max = 512) int rawM) {
        int m = 1 + (rawM % n); // 1 <= m <= n
        List<byte[]> leaves = CryptoTestSupport.randomLeafHashes(n, 17L * n + m);
        byte[] oldRoot = MerkleTreeHash.mth(leaves.subList(0, m));
        byte[] newRoot = MerkleTreeHash.mth(leaves);
        List<byte[]> proof = ConsistencyProof.generate(leaves, m, n);
        assertThat(ConsistencyVerifier.verify(m, n, oldRoot, newRoot, proof)).isTrue();
    }

    /** INVARIANT 3 (negative): mutating any leaf invalidates its inclusion proof. */
    @Property(tries = 1000)
    void tamperedLeafFailsVerification(
            @ForAll @IntRange(min = 2, max = 256) int n,
            @ForAll @IntRange(min = 0, max = Integer.MAX_VALUE) int rawI,
            @ForAll @IntRange(min = 0, max = 255) int bit) {
        int i = rawI % n;
        List<byte[]> leaves = CryptoTestSupport.randomLeafHashes(n, 7L * n + i);
        byte[] root = MerkleTreeHash.mth(leaves);
        List<byte[]> path = InclusionProof.generate(leaves, i, n);
        byte[] tampered = CryptoTestSupport.flipOneBit(leaves.get(i), bit);
        assertThat(InclusionVerifier.verify(tampered, i, n, path, root)).isFalse();
    }

    /** INVARIANT 4: the optimized cached root equals the reference MTH for every size. */
    @Property(tries = 1000)
    void cachedRootEqualsReferenceRoot(
            @ForAll @IntRange(min = 1, max = 1024) int n,
            @ForAll @LongRange(min = 0, max = Long.MAX_VALUE) long seed) {
        List<byte[]> leaves = CryptoTestSupport.randomLeafHashes(n, seed);
        assertThat(CachedMerkleTree.of(leaves).root()).isEqualTo(MerkleTreeHash.mth(leaves));
    }
}
