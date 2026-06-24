package dev.hg.etchlog.server.security;

/**
 * Decides whether a presented appender key is currently valid. Abstracted behind an interface so
 * the {@link ApiKeyAuthFilter} stays free of persistence concerns and is trivially unit-testable,
 * and so the backing store (today the {@code api_keys} table) can change without touching the
 * filter.
 *
 * @see DbApiKeyAuthenticator
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
public interface ApiKeyAuthenticator {

    /**
     * Whether {@code presentedKey} matches an <em>active</em> appender credential. Implementations
     * must treat a revoked or unknown key as invalid and must not leak, via timing or otherwise,
     * which stored key (if any) a near-miss guess was close to.
     *
     * @param presentedKey the raw key from the {@code X-Api-Key} header (already trimmed,
     *     non-blank)
     */
    boolean isValidAppenderKey(String presentedKey);
}
