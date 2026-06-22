package dev.hg.etchlog.core.hash;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class MerkleHashTest {

    private static final HexFormat HEX = HexFormat.of();

    /** RFC 6962 known vector: leaf hash of the empty string = SHA-256(0x00). */
    @Test
    void leafHashOfEmptyMatchesRfc6962Vector() {
        assertThat(HEX.formatHex(MerkleHash.hashLeaf(new byte[0])))
                .isEqualTo("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
    }

    /**
     * RFC 6962 §2.1 known vector: the empty-tree head MTH({}) = SHA-256("") — the empty string with
     * NO leaf prefix. Must differ from the leaf hash of empty data (which carries the 0x00 prefix).
     */
    @Test
    void emptyTreeHashMatchesRfc6962Vector() {
        assertThat(HEX.formatHex(MerkleHash.emptyTreeHash()))
                .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assertThat(MerkleHash.emptyTreeHash())
                .as("empty-tree hash must NOT carry the 0x00 leaf prefix")
                .isNotEqualTo(MerkleHash.hashLeaf(new byte[0]));
    }

    /** Domain separation: a leaf and a node over the same bytes must differ. */
    @Test
    void leafAndNodePrefixesProduceDifferentHashes() {
        byte[] a = MerkleHash.hashLeaf(new byte[0]);
        byte[] b = MerkleHash.hashLeaf(new byte[0]);
        byte[] node = MerkleHash.hashChildren(a, b);
        // node = SHA-256(0x01 || a || b); a leaf over (a||b) would use 0x00 and must differ.
        byte[] leafOverConcat = MerkleHash.hashLeaf(concat(a, b));
        assertThat(node).isNotEqualTo(leafOverConcat);
    }

    @Test
    void hashLengthIs32() {
        assertThat(MerkleHash.hashLeaf(new byte[] {1, 2, 3})).hasSize(MerkleHash.HASH_LENGTH);
    }

    @Test
    void nullInputsAreRejected() {
        assertThatThrownBy(() -> MerkleHash.hashLeaf(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MerkleHash.hashChildren(null, new byte[1]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static byte[] concat(byte[] x, byte[] y) {
        byte[] out = new byte[x.length + y.length];
        System.arraycopy(x, 0, out, 0, x.length);
        System.arraycopy(y, 0, out, x.length, y.length);
        return out;
    }
}
