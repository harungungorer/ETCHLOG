package dev.hg.etchlog.server.security;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Appender API keys, supplied as configuration under {@code etchlog.security} and hashed once at
 * startup. The raw keys come from environment variables / a secret manager in production and the
 * plaintext is discarded after hashing — only the {@link #resolvedKeyHashes() hashes} live in
 * memory.
 *
 * <p>Accepting a <em>set</em> of keys is what makes zero-downtime rotation possible: list both the
 * old and new key during the overlap window, migrate appenders, then drop the old one. Revocation
 * is removing a key from this set and restarting.
 *
 * @param apiKeys the raw appender keys; each is SHA-256 hashed at startup
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
@ConfigurationProperties(prefix = "etchlog.security")
public record ApiKeyProperties(List<String> apiKeys) {

    /**
     * The well-known demo key. Intentionally public; gated behind the {@code demo} profile (see
     * {@code application-demo.yml}) and never a production default.
     */
    public static final String DEMO_API_KEY = "etchlog-demo-key-change-me";

    /**
     * Hashes every configured non-blank key once. Fails fast when none are configured, because a
     * running server whose only write endpoint is unreachable is almost always a misconfiguration —
     * not the intended "public read-only" state.
     *
     * @throws IllegalStateException when no usable key is configured
     */
    public Set<String> resolvedKeyHashes() {
        Set<String> hashes =
                apiKeys == null
                        ? Set.of()
                        : apiKeys.stream()
                                .filter(k -> k != null && !k.isBlank())
                                .map(String::trim)
                                .map(ApiKeyHasher::sha256Hex)
                                .collect(Collectors.toUnmodifiableSet());
        if (hashes.isEmpty()) {
            throw new IllegalStateException(
                    "No etchlog.security.api-keys configured — the append endpoint would be"
                            + " unreachable. Set ETCHLOG_SECURITY_API_KEYS, or run with the 'demo'"
                            + " profile for the built-in demo key.");
        }
        return hashes;
    }

    /**
     * Whether the well-known demo key is among the configured keys (drives a loud startup WARN).
     */
    public boolean usesDemoKey() {
        return apiKeys != null
                && apiKeys.stream().anyMatch(k -> k != null && DEMO_API_KEY.equals(k.trim()));
    }
}
