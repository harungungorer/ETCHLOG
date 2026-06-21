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
 * @param signature Ed25519 signature over {@link SthEncoding#bytesToSign}
 */
public record SignedTreeHead(long treeSize, byte[] rootHash, long timestamp, byte[] signature) {

    public SignedTreeHead {
        if (treeSize < 0) {
            throw new IllegalArgumentException("treeSize must be non-negative");
        }
        if (rootHash == null || rootHash.length != MerkleHash.HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "rootHash must be " + MerkleHash.HASH_LENGTH + " bytes");
        }
        if (signature == null) {
            throw new IllegalArgumentException("signature must not be null");
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
