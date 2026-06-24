package dev.hg.etchlog.server.security;

import dev.hg.etchlog.server.persistence.entity.ApiKeyEntity;
import dev.hg.etchlog.server.persistence.repository.ApiKeyRepository;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Bootstraps the configured {@code etchlog.security.api-keys} into the {@code api_keys} table at
 * startup so the database — the runtime source of truth consulted by {@link DbApiKeyAuthenticator}
 * — always knows about the operator's configured keys.
 *
 * <p>Seeding is purely additive and idempotent: a key already present (by hash) is left untouched,
 * which is what lets an operator revoke a configured key in the database ({@code active = false})
 * and have it <em>stay</em> revoked across restarts even though it is still listed in config. Runs
 * after Flyway and JPA are ready (it is an {@link ApplicationRunner}); the append endpoint is only
 * driven by operators, never in the sub-millisecond window before this runner completes.
 *
 * @see ApiKeyProperties
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
@Component
public class ApiKeySeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ApiKeySeeder.class);

    private final ApiKeyProperties properties;
    private final ApiKeyRepository apiKeys;

    public ApiKeySeeder(ApiKeyProperties properties, ApiKeyRepository apiKeys) {
        this.properties = properties;
        this.apiKeys = apiKeys;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        int seeded = 0;
        int existing = 0;
        for (String key : properties.normalizedKeys()) {
            byte[] hash = ApiKeyHasher.sha256Bytes(key);
            if (apiKeys.findByKeyHash(hash).isPresent()) {
                existing++;
                continue;
            }
            // Label is the hash prefix only — identifiable in the table, never the key itself.
            String label = "config-seeded-" + HexFormat.of().formatHex(hash, 0, 4);
            apiKeys.save(new ApiKeyEntity(hash, label));
            seeded++;
        }
        log.info(
                "Appender key seeding complete: {} newly seeded, {} already present. Revoke a key in"
                        + " the api_keys table (active=false) to disable it without a restart.",
                seeded,
                existing);
    }
}
