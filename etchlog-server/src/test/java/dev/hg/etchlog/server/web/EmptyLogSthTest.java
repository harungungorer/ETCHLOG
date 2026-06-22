package dev.hg.etchlog.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.etchlog.core.sth.SthVerifier;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * {@code GET /api/v1/log/sth} on a brand-new, empty log must return the documented genesis STH:
 * {@code tree_size = 0} with the RFC 6962 empty-tree hash {@code SHA-256("")}, signed so it still
 * verifies under the log key. Uses its own temp SQLite database so the log is genuinely empty.
 */
@SpringBootTest
@AutoConfigureMockMvc
class EmptyLogSthTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-empty.db"));
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired PublicKey logPublicKey;

    @Test
    void emptyLogReturnsSignedGenesisSth() throws Exception {
        JsonNode sth =
                json.readTree(
                        mvc.perform(get("/api/v1/log/sth"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.tree_size").value(0))
                                .andReturn()
                                .getResponse()
                                .getContentAsString());

        byte[] root = Base64.getDecoder().decode(sth.get("root_hash").asText());
        byte[] sig = Base64.getDecoder().decode(sth.get("ed25519_signature").asText());
        long ts = sth.get("timestamp").asLong();

        byte[] emptyHash = MessageDigest.getInstance("SHA-256").digest(new byte[0]);
        assertThat(root)
                .as("RFC 6962 empty-tree hash is SHA-256 of the empty string")
                .isEqualTo(emptyHash);
        assertThat(SthVerifier.verify(logPublicKey, 0, ts, root, sig)).isTrue();
    }
}
