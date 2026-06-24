package dev.hg.etchlog.server.demo;

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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Verifies the demo tamper endpoint is reachable and functional <strong>only</strong> under the
 * {@code demo} profile, and that it really mutates the stored record (the returned tampered hash
 * matches the leaf the read endpoint subsequently serves).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("demo")
class DemoTamperWebTest {

    private static final String KEY = "test-api-key";

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void config(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-demo-web.db"));
        // Pin the appender key deterministically (highest-precedence source).
        registry.add("etchlog.security.api-keys[0]", () -> KEY);
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired org.springframework.context.ApplicationContext ctx;

    @Test
    void demoProfileWarningBeanIsRegistered() {
        // The loud startup-warning guard must be wired whenever the demo profile is active.
        org.assertj.core.api.Assertions.assertThat(ctx.getBeansOfType(DemoProfileWarning.class))
                .hasSize(1);
    }

    private static String body(String text) {
        return "{\"leaf_data\":\"" + Base64.getEncoder().encodeToString(text.getBytes()) + "\"}";
    }

    @Test
    void tamperIsReachableAndMutatesTheStoredLeaf() throws Exception {
        mvc.perform(
                        post("/api/v1/log/entries")
                                .header("X-Api-Key", KEY)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body("original-record")))
                .andExpect(status().isCreated());

        String tampered =
                mvc.perform(post("/api/v1/_demo/tamper/{index}", 0))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.leaf_index").value(0))
                        .andExpect(jsonPath("$.tampered_leaf_data").isString())
                        .andExpect(jsonPath("$.tampered_leaf_hash").isString())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String tamperedHash = json.readTree(tampered).get("tampered_leaf_hash").asText();

        // The read endpoint now serves the mutated leaf — its hash matches what tamper reported.
        JsonNode entry =
                json.readTree(
                        mvc.perform(get("/api/v1/log/entries/{index}", 0))
                                .andExpect(status().isOk())
                                .andReturn()
                                .getResponse()
                                .getContentAsString());
        org.assertj.core.api.Assertions.assertThat(entry.get("leaf_hash").asText())
                .isEqualTo(tamperedHash);
    }

    @Test
    void tamperingAMissingLeafReturnsProblemJson404() throws Exception {
        // DemoExceptionHandler renders the demo 404 as application/problem+json (with type and
        // timestamp), matching the main API instead of a bare framework error body.
        mvc.perform(post("/api/v1/_demo/tamper/{index}", 9_999))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.type").value("https://etchlog.dev/problems/leaf-not-found"))
                .andExpect(jsonPath("$.title").value("Leaf Not Found"))
                .andExpect(jsonPath("$.timestamp").isNumber());
    }
}
