package dev.hg.etchlog.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.etchlog.core.sth.SthVerifier;
import java.nio.file.Path;
import java.security.PublicKey;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * End-to-end contract test for {@code POST /api/v1/log/entries} over the full Spring stack (real
 * {@link dev.hg.etchlog.server.log.LogService}, JPA/Flyway on temp SQLite, the appender-auth
 * security filter, and the application-wide snake_case + Base64 JSON conventions). Confirms the
 * response shape and — crucially — that the returned STH actually verifies under the log's public
 * key, plus the documented 400/409 error behaviours. Every append carries the test {@code
 * X-Api-Key}; the dedicated {@link AppendAuthorizationTest} covers the auth boundary itself.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LogControllerTest {

    /** Matches the key configured in {@code src/test/resources/application.properties}. */
    private static final String API_KEY = "test-api-key";

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url", () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-web.db"));
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired PublicKey logPublicKey;

    private static String body(String leafDataBase64) {
        return "{\"leaf_data\":\"" + leafDataBase64 + "\"}";
    }

    /** An authenticated append request with the given JSON body. */
    private static MockHttpServletRequestBuilder appendRequest(String jsonBody) {
        return post("/api/v1/log/entries")
                .header("X-Api-Key", API_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonBody);
    }

    @Test
    void appendReturns201WithAVerifiableSth() throws Exception {
        String payload = Base64.getEncoder().encodeToString("hello etchlog".getBytes());

        MvcResult res =
                mvc.perform(appendRequest(body(payload)))
                        .andExpect(status().isCreated())
                        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                        .andExpect(jsonPath("$.leaf_index").isNumber())
                        .andExpect(jsonPath("$.sth.root_hash").isString())
                        .andExpect(jsonPath("$.sth.ed25519_signature").isString())
                        .andReturn();

        JsonNode root = json.readTree(res.getResponse().getContentAsString());
        long leafIndex = root.get("leaf_index").asLong();
        JsonNode sth = root.get("sth");
        long treeSize = sth.get("tree_size").asLong();
        // tree_size is always leaf_index + 1 regardless of how many entries preceded this one.
        assertThat(treeSize).isEqualTo(leafIndex + 1);
        long timestamp = sth.get("timestamp").asLong();
        byte[] rootHash = Base64.getDecoder().decode(sth.get("root_hash").asText());
        byte[] signature = Base64.getDecoder().decode(sth.get("ed25519_signature").asText());

        assertThat(rootHash).hasSize(32);
        assertThat(signature).hasSize(64);
        assertThat(SthVerifier.verify(logPublicKey, treeSize, timestamp, rootHash, signature))
                .as("the STH returned by the append endpoint must verify under the log key")
                .isTrue();
    }

    @Test
    void missingLeafDataIsRejectedWithProblemDetail() throws Exception {
        mvc.perform(appendRequest("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.title").isString())
                .andExpect(jsonPath("$.type").isString())
                .andExpect(jsonPath("$.instance").value("/api/v1/log/entries"))
                .andExpect(jsonPath("$.timestamp").isNumber());
    }

    @Test
    void emptyLeafDataIsRejected() throws Exception {
        mvc.perform(appendRequest(body(""))).andExpect(status().isBadRequest());
    }

    @Test
    void invalidBase64IsRejected() throws Exception {
        mvc.perform(appendRequest(body("@@@not-base64@@@"))).andExpect(status().isBadRequest());
    }

    @Test
    void duplicateAppendReturns409() throws Exception {
        String payload = Base64.getEncoder().encodeToString("dup-record".getBytes());
        mvc.perform(appendRequest(body(payload))).andExpect(status().isCreated());
        mvc.perform(appendRequest(body(payload)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }
}
