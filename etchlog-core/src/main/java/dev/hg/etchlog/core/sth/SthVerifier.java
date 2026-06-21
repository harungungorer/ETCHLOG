package dev.hg.etchlog.core.sth;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Standalone Ed25519 STH signature verification.
 *
 * <p>A verifier needs only the log's Ed25519 <em>public</em> key plus the STH fields — no database
 * access and no server trust. Any alteration of {@code treeSize}, {@code timestamp}, or {@code
 * rootHash} invalidates the signature.
 */
public final class SthVerifier {

    private SthVerifier() {}

    /** Verifies a signature over the canonical bytes for the given STH fields. */
    public static boolean verify(
            PublicKey logPublicKey,
            long treeSize,
            long timestampMs,
            byte[] rootHash,
            byte[] signature) {
        if (logPublicKey == null || rootHash == null || signature == null) {
            return false;
        }
        try {
            byte[] msg = SthEncoding.bytesToSign(treeSize, timestampMs, rootHash);
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(logPublicKey);
            sig.update(msg);
            return sig.verify(signature); // false if any signed field was altered
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** Verifies a fully-formed {@link SignedTreeHead}. */
    public static boolean verify(PublicKey logPublicKey, SignedTreeHead sth) {
        if (sth == null) {
            return false;
        }
        return verify(
                logPublicKey, sth.treeSize(), sth.timestamp(), sth.rootHash(), sth.signature());
    }
}
