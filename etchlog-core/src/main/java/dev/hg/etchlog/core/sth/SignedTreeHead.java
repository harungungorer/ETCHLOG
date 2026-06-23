package dev.hg.etchlog.core.sth;

import dev.hg.etchlog.core.hash.MerkleHash;

/**
 * The log's tamper-evident commitment to its current state: a Signed Tree Head.
 *
 * <p>Immutable value object. {@code rootHash} and {@code signature} are defensively copied so the
 * STH cannot be mutated after construction.
 *
 * @param treeSize number of leaves committed ({@code N}); the root is the MTH over leaves {@code
 *     0..N-1}
 * @param rootHash 32-byte RFC 6962 tree head over those leaves
 * @param timestamp epoch-millisecond instant the STH was issued
 * @param signature fixed-length {@value #SIGNATURE_LENGTH}-byte Ed25519 signature over {@link
 *     SthEncoding#bytesToSign}
 */
public record SignedTreeHead(long treeSize, byte[] rootHash, long timestamp, byte[] signature) {

    /**
     * Byte length of an Ed25519 signature — the only signature scheme Etchlog uses for STHs. The
     * compact constructor enforces it so a malformed or truncated signature (e.g. a wire response
     * that was cut short, or a zero-length placeholder) is rejected at construction rather than
     * silently producing an STH that can never verify.
     */
    public static final int SIGNATURE_LENGTH = 64;

    public SignedTreeHead {
        if (treeSize < 0) {
            throw new IllegalArgumentException("treeSize must be non-negative");
        }
        if (rootHash == null || rootHash.length != MerkleHash.HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "rootHash must be " + MerkleHash.HASH_LENGTH + " bytes");
        }
        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            throw new IllegalArgumentException(
                    "signature must be " + SIGNATURE_LENGTH + " bytes (Ed25519)");
        }
        rootHash = rootHash.clone();
        signature = signature.clone();
    }

    @Override
    public byte[] rootHash() {
        return rootHash.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    /** The canonical bytes this STH's signature covers. */
    public byte[] bytesToSign() {
        return SthEncoding.bytesToSign(treeSize, timestamp, rootHash);
    }
}
