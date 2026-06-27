package dev.hg.etchlog.server.health;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.etchlog.server.config.SigningKeyFingerprint;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

/**
 * Unit tests for the {@link SigningKeyHealthIndicator} and the {@link SigningKeyFingerprint} it
 * exposes. These pin the operator-facing contract documented in the ops guides: a {@code
 * signingKey} health component reporting {@code UP} with the algorithm and a SHA-256-of-DER
 * public-key fingerprint that operators can independently reproduce with {@code openssl}.
 */
class SigningKeyHealthIndicatorTest {

    private static PublicKey ed25519PublicKey() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic();
    }

    @Test
    void reportsUpWithAlgorithmAndFingerprint() throws Exception {
        PublicKey pub = ed25519PublicKey();

        Health health = new SigningKeyHealthIndicator(pub).health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("algorithm", "Ed25519");
        assertThat(health.getDetails().get("keyFingerprint"))
                .isEqualTo(SigningKeyFingerprint.of(pub));
    }

    @Test
    void reportsDownWhenNoKeyLoaded() {
        Health health = new SigningKeyHealthIndicator(null).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).doesNotContainKey("keyFingerprint");
    }

    /**
     * The fingerprint must equal the SHA-256 of the public key's DER (X.509/SPKI) encoding, in
     * lowercase hex — exactly what {@code openssl pkey -pubin -outform DER | openssl dgst -sha256}
     * yields. Recompute it independently here so an accidental change to the algorithm, encoding,
     * or hex casing breaks this test rather than silently diverging from the documented pin.
     */
    @Test
    void fingerprintMatchesSha256OfDerEncoding() throws Exception {
        PublicKey pub = ed25519PublicKey();

        byte[] expected = MessageDigest.getInstance("SHA-256").digest(pub.getEncoded());
        String fingerprint = SigningKeyFingerprint.of(pub);

        assertThat(fingerprint).isEqualTo(HexFormat.of().formatHex(expected));
        assertThat(fingerprint).hasSize(64).matches("[0-9a-f]{64}");
    }

    /** Distinct keys must yield distinct fingerprints, and the same key a stable one. */
    @Test
    void fingerprintIsStablePerKeyAndDistinctAcrossKeys() throws Exception {
        PublicKey a = ed25519PublicKey();
        PublicKey b = ed25519PublicKey();

        assertThat(SigningKeyFingerprint.of(a)).isEqualTo(SigningKeyFingerprint.of(a));
        assertThat(SigningKeyFingerprint.of(a)).isNotEqualTo(SigningKeyFingerprint.of(b));
    }
}
