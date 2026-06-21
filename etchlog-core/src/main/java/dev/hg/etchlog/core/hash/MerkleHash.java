package dev.hg.etchlog.core.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * RFC 6962 §2.1 Merkle hashing. Pure, allocation-light, no framework deps.
 *
 * <p>The {@code 0x00} / {@code 0x01} prefixes are DOMAIN SEPARATORS: they guarantee that the hash
 * of a leaf can never collide with the hash of an interior node, which blocks second-preimage
 * attacks against the tree structure.
 *
 * <pre>
 *   leaf hash      = SHA-256( 0x00 || leaf_data )
 *   interior node  = SHA-256( 0x01 || left_hash || right_hash )
 * </pre>
 */
public final class MerkleHash {

    private static final byte LEAF_PREFIX = 0x00;
    private static final byte NODE_PREFIX = 0x01;

    /** Length, in bytes, of a SHA-256 digest. */
    public static final int HASH_LENGTH = 32;

    private MerkleHash() {}

    /** Leaf hash: {@code SHA-256(0x00 || leafData)}. */
    public static byte[] hashLeaf(byte[] leafData) {
        if (leafData == null) {
            throw new IllegalArgumentException("leafData must not be null");
        }
        MessageDigest md = sha256();
        md.update(LEAF_PREFIX); // domain separation: this is a LEAF
        md.update(leafData);
        return md.digest();
    }

    /** Interior node hash: {@code SHA-256(0x01 || left || right)}. */
    public static byte[] hashChildren(byte[] left, byte[] right) {
        if (left == null || right == null) {
            throw new IllegalArgumentException("child hashes must not be null");
        }
        MessageDigest md = sha256();
        md.update(NODE_PREFIX); // domain separation: this is a NODE
        md.update(left);
        md.update(right);
        return md.digest();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on the JDK", e);
        }
    }
}
