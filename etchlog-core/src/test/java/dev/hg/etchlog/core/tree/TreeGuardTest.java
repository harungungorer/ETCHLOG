package dev.hg.etchlog.core.tree;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.core.CryptoTestSupport;
import dev.hg.etchlog.core.hash.MerkleHash;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Guard / accessor coverage for the two tree-head implementations. The cross-checked happy paths
 * live in the property suite and {@link EmptyTreeHashTest}; this pins null rejection and the {@code
 * size()} accessor.
 */
class TreeGuardTest {

    @Test
    void referenceMthRejectsNull() {
        assertThatThrownBy(() -> MerkleTreeHash.mth(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void cachedTreeRejectsNull() {
        assertThatThrownBy(() -> CachedMerkleTree.of(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void cachedTreeReportsLeafCount() {
        List<byte[]> leaves = CryptoTestSupport.randomLeafHashes(6, 99L);
        assertThat(CachedMerkleTree.of(leaves).size()).isEqualTo(6);
        assertThat(CachedMerkleTree.of(List.of()).size()).isZero();
    }

    @Test
    void hashChildrenRejectsNullRightChild() {
        // MerkleHashTest covers the null-left side; this pins the null-right branch.
        assertThatThrownBy(() -> MerkleHash.hashChildren(new byte[1], null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
