package dev.hg.etchlog.server.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

/**
 * The appender-authorization boundary (Milestone 4): the single write endpoint requires a valid
 * {@code X-Api-Key}, while every read/proof/STH endpoint is public. A missing or wrong key is
 * rejected with {@code 401} rendered as {@code application/problem+json}; a valid key appends.
 *
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
@SpringBootTest
@AutoConfigureMockMvc
class AppendAuthorizationTest {

    /** Matches the key configured in {@code src/test/resources/application.properties}. */
    private static final String VALID_KEY = "test-api-key";

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url", () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-auth.db"));
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    private static String body(String text) {
        return "{\"leaf_data\":\"" + Base64.getEncoder().encodeToString(text.getBytes()) + "\"}";
    }

    @Test
    void appendWithoutKeyIsUnauthorized() throws Exception {
        mvc.perform(
                        post("/api/v1/log/entries")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body("no-key")))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.title").isString())
                .andExpect(jsonPath("$.type").isString())
                .andExpect(jsonPath("$.timestamp").isNumber());
    }

    @Test
    void appendWithInvalidKeyIsUnauthorized() throws Exception {
        mvc.perform(
                        post("/api/v1/log/entries")
                                .header("X-Api-Key", "totally-wrong-key")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body("wrong-key")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void appendWithValidKeyIsCreated() throws Exception {
        mvc.perform(
                        post("/api/v1/log/entries")
                                .header("X-Api-Key", VALID_KEY)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body("good-key")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.leaf_index").isNumber())
                .andExpect(jsonPath("$.sth.ed25519_signature").isString());
    }

    @Test
    void readEndpointsRequireNoKey() throws Exception {
        // Append one entry (authenticated) so there is something to read back.
        String appended =
                mvc.perform(
                                post("/api/v1/log/entries")
                                        .header("X-Api-Key", VALID_KEY)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(body("public-read")))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        JsonNode node = json.readTree(appended);
        long leafIndex = node.get("leaf_index").asLong();
        long treeSize = node.get("sth").get("tree_size").asLong();

        // The STH, entry, and proof endpoints are public — no credential the operator could revoke.
        mvc.perform(get("/api/v1/log/sth"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tree_size").isNumber());
        mvc.perform(get("/api/v1/log/entries/{index}", leafIndex)).andExpect(status().isOk());
        mvc.perform(
                        get("/api/v1/log/proofs/inclusion")
                                .param("leaf_index", Long.toString(leafIndex))
                                .param("tree_size", Long.toString(treeSize)))
                .andExpect(status().isOk());
    }
}
