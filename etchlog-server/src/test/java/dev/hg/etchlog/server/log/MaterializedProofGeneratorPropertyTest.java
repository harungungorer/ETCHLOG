package dev.hg.etchlog.server.log;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.proof.ConsistencyProof;
import dev.hg.etchlog.core.proof.ConsistencyVerifier;
import dev.hg.etchlog.core.proof.InclusionProof;
import dev.hg.etchlog.core.proof.InclusionVerifier;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import org.junit.jupiter.api.Test;

/**
 * Correctness proof for {@link MaterializedProofGenerator} — the O(log N) proof read path that
 * reads materialized {@code tree_nodes} instead of re-deriving the tree from level-0 leaves.
 *
 * <p>A subtly-wrong proof is a false security claim, so this asserts the new generator is
 * <strong>byte-for-byte identical</strong> to {@code etchlog-core}'s leaf-list generators (the
 * authoritative, independently property-tested RFC 6962 reference) for every {@code (m, n)} — both
 * exhaustively for small trees and randomly for large ones. The in-memory {@link NodeSource} used
 * here is built by replaying {@link LogService}'s exact node-materialization carry, so the test
 * also exercises the real {@code (level, node_index)} addressing and fails loudly if the generator
 * ever requests a node the store would not have materialized.
 */
class MaterializedProofGeneratorPropertyTest {

    /** Upper bound for the exhaustive small-tree sweep (all sizes, all indices/size-pairs). */
    private static final int EXHAUSTIVE_MAX = 40;

    // ---- Exhaustive small-tree coverage -------------------------------------------------

    @Test
    void inclusionMatchesCoreOracleExhaustively() {
        for (int n = 1; n <= EXHAUSTIVE_MAX; n++) {
            List<byte[]> leaves = leaves(n);
            MaterializedProofGenerator.NodeSource source = materialize(leaves);
            for (int m = 0; m < n; m++) {
                assertHashListsEqual(
                        MaterializedProofGenerator.inclusionPath(source, m, n),
                        InclusionProof.generate(leaves, m, n),
                        "inclusion m=" + m + " n=" + n);
            }
        }
    }

    @Test
    void consistencyMatchesCoreOracleExhaustively() {
        for (int n = 1; n <= EXHAUSTIVE_MAX; n++) {
            List<byte[]> leaves = leaves(n);
            MaterializedProofGenerator.NodeSource source = materialize(leaves);
            for (int first = 1; first <= n; first++) {
                for (int second = first; second <= n; second++) {
                    assertHashListsEqual(
                            MaterializedProofGenerator.consistencyProof(source, first, second),
                            ConsistencyProof.generate(leaves, first, second),
                            "consistency first=" + first + " second=" + second);
                }
            }
        }
    }

    // ---- Random large-tree coverage -----------------------------------------------------

    @Property(tries = 400)
    void inclusionMatchesCoreOracleForLargeTrees(
            @ForAll @IntRange(min = 1, max = 4096) int n,
            @ForAll @IntRange(min = 0, max = Integer.MAX_VALUE) int mRaw) {
        int m = mRaw % n;
        List<byte[]> leaves = leaves(n);
        MaterializedProofGenerator.NodeSource source = materialize(leaves);
        assertHashListsEqual(
                MaterializedProofGenerator.inclusionPath(source, m, n),
                InclusionProof.generate(leaves, m, n),
                "inclusion m=" + m + " n=" + n);
    }

    @Property(tries = 400)
    void consistencyMatchesCoreOracleForLargeTrees(
            @ForAll @IntRange(min = 1, max = 4096) int n,
            @ForAll @IntRange(min = 0, max = Integer.MAX_VALUE) int firstRaw,
            @ForAll @IntRange(min = 0, max = Integer.MAX_VALUE) int secondRaw) {
        int first = 1 + (firstRaw % n); // [1, n]
        int second = first + (secondRaw % (n - first + 1)); // [first, n]
        List<byte[]> leaves = leaves(n);
        MaterializedProofGenerator.NodeSource source = materialize(leaves);
        assertHashListsEqual(
                MaterializedProofGenerator.consistencyProof(source, first, second),
                ConsistencyProof.generate(leaves, first, second),
                "consistency first=" + first + " second=" + second);
    }

    // ---- Belt-and-suspenders: generated proofs verify against the real root -------------

    @Test
    void generatedProofsVerifyAgainstTheCommittedRoot() {
        int n = 27; // deliberately non-power-of-two so the right edge is exercised
        List<byte[]> leaves = leaves(n);
        MaterializedProofGenerator.NodeSource source = materialize(leaves);
        byte[] root = MerkleTreeHash.mth(leaves);

        for (int m = 0; m < n; m++) {
            List<byte[]> path = MaterializedProofGenerator.inclusionPath(source, m, n);
            assertThat(InclusionVerifier.verify(leaves.get(m), m, n, path, root))
                    .as("inclusion proof for leaf %d verifies against the size-%d root", m, n)
                    .isTrue();
        }

        for (int first = 1; first < n; first++) {
            byte[] oldRoot = MerkleTreeHash.mth(leaves.subList(0, first));
            List<byte[]> proof = MaterializedProofGenerator.consistencyProof(source, first, n);
            assertThat(ConsistencyVerifier.verify(first, n, oldRoot, root, proof))
                    .as("consistency proof %d->%d verifies", first, n)
                    .isTrue();
        }
    }

    // ---- Helpers ------------------------------------------------------------------------

    /** Distinct, deterministic leaf hashes — content is irrelevant, only ordering/identity. */
    private static List<byte[]> leaves(int n) {
        List<byte[]> leaves = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            leaves.add(MerkleHash.hashLeaf(ByteBuffer.allocate(4).putInt(i).array()));
        }
        return leaves;
    }

    /**
     * Builds a {@link NodeSource} by replaying {@link LogService#materializeCompletedNodes}'s carry
     * exactly: each append stores its level-0 node, then folds completed left-edge subtrees upward.
     * The source throws on a request for a non-materialized node, so the generator is held to only
     * reading nodes the real store would actually hold.
     */
    private static MaterializedProofGenerator.NodeSource materialize(List<byte[]> leaves) {
        Map<Long, byte[]> nodes = new HashMap<>();
        for (int index = 0; index < leaves.size(); index++) {
            int level = 0;
            long nodeIndex = index;
            byte[] hash = leaves.get(index);
            nodes.put(key(level, nodeIndex), hash);
            while ((nodeIndex & 1L) == 1L) {
                byte[] left = nodes.get(key(level, nodeIndex - 1));
                hash = MerkleHash.hashChildren(left, hash);
                level += 1;
                nodeIndex >>= 1;
                nodes.put(key(level, nodeIndex), hash);
            }
        }
        return (level, index) -> {
            byte[] hash = nodes.get(key(level, index));
            if (hash == null) {
                throw new AssertionError(
                        "generator requested non-materialized node (" + level + ", " + index + ")");
            }
            return hash;
        };
    }

    private static long key(int level, long index) {
        return ((long) level << 48) | index;
    }

    private static void assertHashListsEqual(
            List<byte[]> actual, List<byte[]> expected, String ctx) {
        assertThat(actual).as("%s: proof node count", ctx).hasSameSizeAs(expected);
        for (int i = 0; i < expected.size(); i++) {
            assertThat(actual.get(i))
                    .as("%s: proof node %d", ctx, i)
                    .containsExactly(expected.get(i));
        }
    }
}
