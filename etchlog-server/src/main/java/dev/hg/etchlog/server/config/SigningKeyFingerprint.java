package dev.hg.etchlog.server.config;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;

/**
 * Computes the stable fingerprint operators use to pin the log's signing identity.
 *
 * <p>The fingerprint is the SHA-256 digest of the public key's DER (X.509/SPKI) encoding, rendered
 * as lowercase hex. It is deliberately identical to what {@code openssl pkey -pubin -outform DER |
 * openssl dgst -sha256} produces, so an operator can independently derive it from the distributed
 * public PEM and confirm the running server loaded the expected key.
 *
 * <p>This exposes <em>only</em> a one-way digest of the <em>public</em> key — never the private key
 * or raw key material — so it is safe to emit in startup logs and the actuator health endpoint.
 */
public final class SigningKeyFingerprint {

    private SigningKeyFingerprint() {}

    /**
     * Returns the lowercase-hex SHA-256 fingerprint of {@code publicKey}'s DER encoding.
     *
     * @param publicKey the log's published Ed25519 public key
     * @return 64-character lowercase hex digest matching {@code openssl dgst -sha256}
     */
    public static String of(PublicKey publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on the JDK", e);
        }
    }
}
