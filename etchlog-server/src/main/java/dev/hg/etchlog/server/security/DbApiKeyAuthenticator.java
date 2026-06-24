package dev.hg.etchlog.server.security;

import dev.hg.etchlog.server.persistence.repository.ApiKeyRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authenticates appender keys against the {@code api_keys} table, which is the runtime source of
 * truth. A key is valid iff an <em>active</em> row exists whose {@code key_hash} equals the SHA-256
 * of the presented key, so revoking a row ({@code active = false}) rejects it on the very next
 * request — no restart, no config edit.
 *
 * <p><strong>Timing:</strong> the lookup is by the SHA-256 of the <em>whole</em> key against a
 * {@code UNIQUE}-indexed column. An attacker would already need the full key to compute a matching
 * hash, so an indexed equality lookup leaks nothing exploitable about other keys (unlike a
 * character-by-character comparison of the raw key, which the hashing deliberately avoids).
 *
 * <p>This is deliberately <em>not</em> a {@link java.security.MessageDigest#isEqual} compare: there
 * is no second stored secret to compare the presented key against in constant time. The presented
 * key is hashed and used as an index probe; an attacker cannot steer the probe toward a valid hash
 * without already knowing the key, because SHA-256 is preimage-resistant. Any residual timing in
 * the B-tree lookup is a function of the (public) key-hash distribution, not of how many leading
 * bytes of a real key were guessed, so it carries no signal an attacker can act on.
 *
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
@Component
public class DbApiKeyAuthenticator implements ApiKeyAuthenticator {

    private final ApiKeyRepository apiKeys;

    public DbApiKeyAuthenticator(ApiKeyRepository apiKeys) {
        this.apiKeys = apiKeys;
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isValidAppenderKey(String presentedKey) {
        byte[] hash = ApiKeyHasher.sha256Bytes(presentedKey);
        return apiKeys.findByKeyHashAndActiveTrue(hash).isPresent();
    }
}
