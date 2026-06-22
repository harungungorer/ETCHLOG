package dev.hg.etchlog.server.config;

import dev.hg.etchlog.core.sth.Ed25519SthSigner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the log's Ed25519 signing key into the application: the {@link Ed25519SthSigner} the append
 * path uses and the {@link PublicKey} verifiers consume (e.g. via {@code GET /api/v1/sth}
 * metadata).
 *
 * <p>Keys are loaded from the PEM files named in {@link SigningProperties}; when none are
 * configured an ephemeral demo keypair is generated with a loud warning. The private key never
 * leaves this module — the cryptographic core only ever receives the {@link PrivateKey}/{@link
 * PublicKey} objects, never file paths.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SigningProperties.class)
public class SigningConfig {

    private static final Logger log = LoggerFactory.getLogger(SigningConfig.class);

    /** Resolved signing keypair: loaded from configured PEM files, or generated for demo use. */
    public record LogSigningKey(PrivateKey privateKey, PublicKey publicKey) {}

    @Bean
    public LogSigningKey logSigningKey(SigningProperties props) {
        String priv = props.privateKeyPath();
        String pub = props.publicKeyPath();
        if (priv == null || priv.isBlank()) {
            return generateEphemeral();
        }
        if (pub == null || pub.isBlank()) {
            throw new IllegalStateException(
                    "etchlog.signing.private-key-path is set but public-key-path is not; "
                            + "both PEM files are required so verifiers can check STH signatures");
        }
        return loadFromPem(Path.of(priv), Path.of(pub));
    }

    @Bean
    public Ed25519SthSigner sthSigner(LogSigningKey key) {
        return new Ed25519SthSigner(key.privateKey());
    }

    /** The published log public key, consumed by STH metadata and the verifier endpoints. */
    @Bean
    public PublicKey logPublicKey(LogSigningKey key) {
        return key.publicKey();
    }

    /** UTC clock for STH timestamps; isolated as a bean so tests can pin time. */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    private static LogSigningKey generateEphemeral() {
        try {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
            log.warn(
                    """
                    ════════════════════════════════════════════════════════════════════
                    Etchlog is using an EPHEMERAL Ed25519 signing key (no \
                    etchlog.signing.private-key-path configured).
                    This is for DEMO ONLY: a fresh key is minted on every restart, so STHs \
                    signed now will NOT verify after a restart.
                    Configure a persistent keypair before production use. Current public key (SPKI, base64):
                      {}
                    ════════════════════════════════════════════════════════════════════""",
                    pubB64);
            return new LogSigningKey(kp.getPrivate(), kp.getPublic());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 must be available on the JDK", e);
        }
    }

    private static LogSigningKey loadFromPem(Path privatePem, Path publicPem) {
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey =
                    kf.generatePrivate(
                            new PKCS8EncodedKeySpec(decodePem(privatePem, "PRIVATE KEY")));
            PublicKey publicKey =
                    kf.generatePublic(new X509EncodedKeySpec(decodePem(publicPem, "PUBLIC KEY")));
            log.info("Loaded Ed25519 signing key from {}", privatePem);
            return new LogSigningKey(privateKey, publicKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to parse Ed25519 key material", e);
        }
    }

    /** Reads a PEM file and returns the DER bytes between its BEGIN/END armor lines. */
    private static byte[] decodePem(Path pem, String label) {
        String contents;
        try {
            contents = Files.readString(pem);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read PEM key file: " + pem, e);
        }
        String base64 =
                contents.replace("-----BEGIN " + label + "-----", "")
                        .replace("-----END " + label + "-----", "")
                        .replaceAll("\\s", "");
        if (base64.isEmpty()) {
            throw new IllegalStateException(
                    "PEM file " + pem + " contains no '" + label + "' block");
        }
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "PEM file " + pem + " is not valid base64 for label " + label, e);
        }
    }
}
