package dev.hg.etchlog.server.health;

import dev.hg.etchlog.server.config.SigningKeyFingerprint;
import java.security.PublicKey;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Actuator health contributor that surfaces the log's signing identity at {@code
 * /actuator/health}'s {@code signingKey} component (and the {@code readiness} group).
 *
 * <p>A node that cannot sign cannot advance the cryptographic log and should not receive append
 * traffic, so the loaded signing key is a readiness concern. When the key is present the component
 * reports {@code UP} with two details — the algorithm and the public-key {@code keyFingerprint}
 * (see {@link SigningKeyFingerprint}) — letting an authorized operator confirm the running server
 * pinned the expected identity.
 *
 * <p>Only the <em>public</em> key fingerprint is ever exposed; the private key never reaches this
 * component (it receives just the {@link PublicKey} bean). Component details are gated by {@code
 * management.endpoint.health.show-details=when-authorized}, so anonymous probes see only the
 * top-level status.
 */
@Component
public class SigningKeyHealthIndicator implements HealthIndicator {

    private final PublicKey logPublicKey;

    public SigningKeyHealthIndicator(PublicKey logPublicKey) {
        this.logPublicKey = logPublicKey;
    }

    @Override
    public Health health() {
        if (logPublicKey == null) {
            return Health.down().withDetail("signingKey", "Ed25519 public key not loaded").build();
        }
        return Health.up()
                .withDetail("algorithm", "Ed25519")
                .withDetail("keyFingerprint", SigningKeyFingerprint.of(logPublicKey))
                .build();
    }
}
