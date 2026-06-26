package dev.hg.etchlog.core.sth;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * Ed25519 STH signer. Uses the JDK 21 built-in EdDSA provider (no BouncyCastle required).
 *
 * <p>The private key is the single most sensitive secret in the system: whoever holds it can mint
 * STHs that every verifier will trust. Guard it accordingly.
 */
public final class Ed25519SthSigner {

    private final PrivateKey privateKey;

    public Ed25519SthSigner(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey must not be null");
        }
        this.privateKey = privateKey;
    }

    /**
     * Signs the canonical STH bytes for the given fields, returning a 64-byte Ed25519 signature.
     */
    public byte[] sign(long treeSize, long timestampMs, byte[] rootHash) {
        try {
            byte[] msg = SthEncoding.bytesToSign(treeSize, timestampMs, rootHash);
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(msg);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("STH signing failed", e);
        }
    }

    /** Convenience: builds a fully-formed {@link SignedTreeHead} for the given fields. */
    public SignedTreeHead signSth(long treeSize, long timestampMs, byte[] rootHash) {
        byte[] signature = sign(treeSize, timestampMs, rootHash);
        return new SignedTreeHead(treeSize, rootHash, timestampMs, signature);
    }
}
