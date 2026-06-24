package dev.hg.etchlog.server.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.hg.etchlog.server.persistence.entity.ApiKeyEntity;
import dev.hg.etchlog.server.persistence.repository.ApiKeyRepository;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * The {@code api_keys} table is the runtime source of truth for appender authorization: keys can be
 * issued and revoked in the database and take effect on the next request, with no restart. These
 * tests use their own dedicated keys (never the shared {@code test-api-key}) so they don't disturb
 * sibling tests in the same context.
 *
 * @see DbApiKeyAuthenticator
 * @see ApiKeySeeder
 */
@SpringBootTest
@AutoConfigureMockMvc
class ApiKeyRevocationTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-revocation.db"));
    }

    @Autowired MockMvc mvc;
    @Autowired ApiKeyRepository apiKeys;

    private static MockHttpServletRequestBuilder append(String key, String text) {
        String body =
                "{\"leaf_data\":\"" + Base64.getEncoder().encodeToString(text.getBytes()) + "\"}";
        return post("/api/v1/log/entries")
                .header("X-Api-Key", key)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);
    }

    @Test
    void seedsConfiguredKeysIntoTheTableAtStartup() {
        // The configured test-api-key (src/test/resources/application.properties) was seeded
        // active.
        var seeded = apiKeys.findByKeyHash(ApiKeyHasher.sha256Bytes("test-api-key"));
        assertThat(seeded).isPresent();
        assertThat(seeded.get().isActive()).isTrue();
    }

    @Test
    void appendsWithAKeyIssuedDirectlyIntoTheDatabase() throws Exception {
        String key = "issued-via-db-key";
        apiKeys.save(new ApiKeyEntity(ApiKeyHasher.sha256Bytes(key), "issued-via-db"));

        mvc.perform(append(key, "issued-key-append")).andExpect(status().isCreated());
    }

    @Test
    void revokingAKeyInTheDatabaseRejectsItWithoutRestart() throws Exception {
        String key = "revoke-me-key";
        apiKeys.save(new ApiKeyEntity(ApiKeyHasher.sha256Bytes(key), "revoke-me"));

        // Active → append succeeds.
        mvc.perform(append(key, "before-revoke")).andExpect(status().isCreated());

        // Revoke the row in place (no restart, no config change).
        ApiKeyEntity stored = apiKeys.findByKeyHash(ApiKeyHasher.sha256Bytes(key)).orElseThrow();
        stored.revoke();
        apiKeys.save(stored);

        // The very next request with the same key is now unauthorized.
        mvc.perform(append(key, "after-revoke")).andExpect(status().isUnauthorized());
    }
}
