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
 * old and new key during the overlap window, migrate appenders, then drop the old one.
 *
 * <p><strong>These configured keys are a bootstrap seed, not the runtime source of truth.</strong>
 * At startup {@code ApiKeySeeder} inserts each one into the {@code api_keys} table (if absent), and
 * the {@code DbApiKeyAuthenticator} authenticates every append against the <em>active</em> rows of
 * that table. Revocation therefore happens in the database — set a row's {@code active = false} (or
 * {@code revoked_at}) and it takes effect on the next request, no restart required. Seeding never
 * reactivates a row that was already revoked, so a revoked key stays revoked even while it remains
 * listed here.
 *
 * @param apiKeys the raw appender keys; each is SHA-256 hashed and seeded at startup
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
                normalizedKeys().stream()
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
     * The configured keys with blanks dropped and surrounding whitespace trimmed — the raw form the
     * startup seeder hashes into {@code api_keys}. Returns an empty list (never null) when nothing
     * is configured; the fail-closed check lives in {@link #resolvedKeyHashes()}.
     */
    public List<String> normalizedKeys() {
        return apiKeys == null
                ? List.of()
                : apiKeys.stream()
                        .filter(k -> k != null && !k.isBlank())
                        .map(String::trim)
                        .toList();
    }

    /**
     * Whether the well-known demo key is among the configured keys (drives a loud startup WARN).
     */
    public boolean usesDemoKey() {
        return apiKeys != null
                && apiKeys.stream().anyMatch(k -> k != null && DEMO_API_KEY.equals(k.trim()));
    }
}
