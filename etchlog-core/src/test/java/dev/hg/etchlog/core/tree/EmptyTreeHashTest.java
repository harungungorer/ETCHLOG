package dev.hg.etchlog.core.tree;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Regression guard for the empty-tree head. RFC 6962 §2.1 defines {@code MTH({}) = SHA-256("")}
 * (the empty string with no domain-separation prefix). Both the reference {@link MerkleTreeHash}
 * and the optimized {@link CachedMerkleTree} must agree on that exact value — a single
 * missing/extra prefix byte here is a strict conformance defect, so it is pinned to the known
 * vector.
 */
class EmptyTreeHashTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String EMPTY_TREE_HEX =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Test
    void referenceMthOfEmptyMatchesRfc6962Vector() {
        assertThat(HEX.formatHex(MerkleTreeHash.mth(List.of()))).isEqualTo(EMPTY_TREE_HEX);
    }

    @Test
    void cachedTreeOfEmptyMatchesRfc6962Vector() {
        assertThat(HEX.formatHex(CachedMerkleTree.of(List.of()).root())).isEqualTo(EMPTY_TREE_HEX);
    }

    @Test
    void bothImplementationsAgreeWithCoreHelper() {
        byte[] expected = MerkleHash.emptyTreeHash();
        assertThat(MerkleTreeHash.mth(List.of())).isEqualTo(expected);
        assertThat(CachedMerkleTree.of(List.of()).root()).isEqualTo(expected);
    }
}
