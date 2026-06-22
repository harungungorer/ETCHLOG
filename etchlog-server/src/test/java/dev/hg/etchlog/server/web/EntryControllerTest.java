package dev.hg.etchlog.server.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
import org.springframework.test.web.servlet.MvcResult;

/**
 * Full-stack contract tests for the read endpoints:
 *
 * <ul>
 *   <li>{@code GET /api/v1/log/entries/{index}}
 *   <li>{@code GET /api/v1/log/entries?hash=<base64url>}
 * </ul>
 *
 * <p>Uses the same Spring setup as {@link LogControllerTest} (real {@link
 * dev.hg.etchlog.server.log.LogService}, JPA/Flyway on a distinct temp SQLite file). The temp DB is
 * shared across all tests in this class; tests therefore assert relational invariants (e.g. {@code
 * tree_size == leaf_index + 1}) rather than absolute indices.
 */
@SpringBootTest
@AutoConfigureMockMvc
class EntryControllerTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-entry.db"));
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    private static String body(String leafDataBase64) {
        return "{\"leaf_data\":\"" + leafDataBase64 + "\"}";
    }

    /**
     * Appends a record and returns the parsed response tree. Each caller passes a unique payload so
     * no duplicate-409 is triggered on the shared temp DB.
     */
    private JsonNode appendEntry(String uniquePayload) throws Exception {
        String b64 = Base64.getEncoder().encodeToString(uniquePayload.getBytes());
        MvcResult res =
                mvc.perform(
                                post("/api/v1/log/entries")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(body(b64)))
                        .andExpect(status().isCreated())
                        .andReturn();
        return json.readTree(res.getResponse().getContentAsString());
    }

    @Test
    void getByIndexReturns200WithCorrectFields() throws Exception {
        JsonNode appended = appendEntry("entry-ctrl-test-by-index");
        long leafIndex = appended.get("leaf_index").asLong();

        mvc.perform(get("/api/v1/log/entries/{index}", leafIndex))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.leaf_index").value(leafIndex))
                .andExpect(jsonPath("$.leaf_data").isString())
                .andExpect(jsonPath("$.leaf_hash").isString());
    }

    @Test
    void getByIndexReturnsCorrectLeafData() throws Exception {
        String originalPayload = "entry-ctrl-test-leaf-data-roundtrip";
        String originalBase64 = Base64.getEncoder().encodeToString(originalPayload.getBytes());
        JsonNode appended = appendEntry(originalPayload);
        long leafIndex = appended.get("leaf_index").asLong();

        MvcResult res =
                mvc.perform(get("/api/v1/log/entries/{index}", leafIndex))
                        .andExpect(status().isOk())
                        .andReturn();

        JsonNode body = json.readTree(res.getResponse().getContentAsString());
        // leaf_data is standard Base64; must round-trip to the original payload
        String returnedBase64 = body.get("leaf_data").asText();
        byte[] returnedBytes = Base64.getDecoder().decode(returnedBase64);
        org.assertj.core.api.Assertions.assertThat(returnedBytes)
                .isEqualTo(originalPayload.getBytes());
    }

    @Test
    void getByHashReturns200WithCorrectLeafIndex() throws Exception {
        JsonNode appended = appendEntry("entry-ctrl-test-by-hash");
        long leafIndex = appended.get("leaf_index").asLong();

        // The STH's root_hash is in the response; the leaf_hash comes from GET-by-index
        MvcResult indexRes =
                mvc.perform(get("/api/v1/log/entries/{index}", leafIndex))
                        .andExpect(status().isOk())
                        .andReturn();
        JsonNode indexBody = json.readTree(indexRes.getResponse().getContentAsString());
        String leafHashStdBase64 = indexBody.get("leaf_hash").asText();

        // Convert standard Base64 → raw bytes → Base64URL (no padding) for the query param
        byte[] leafHashBytes = Base64.getDecoder().decode(leafHashStdBase64);
        String leafHashUrlB64 =
                Base64.getUrlEncoder().withoutPadding().encodeToString(leafHashBytes);

        mvc.perform(get("/api/v1/log/entries").param("hash", leafHashUrlB64))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.leaf_index").value(leafIndex));
    }

    @Test
    void getByIndexForMissingLeafReturns404() throws Exception {
        mvc.perform(get("/api/v1/log/entries/999999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.title").isString());
    }

    @Test
    void getByHashWithInvalidBase64UrlReturns400() throws Exception {
        mvc.perform(get("/api/v1/log/entries").param("hash", "@@@notbase64@@@"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getByHashWithWrongLengthReturns400() throws Exception {
        // Well-formed Base64URL, but decodes to 4 bytes — not a 32-byte SHA-256 leaf hash.
        String shortHash =
                Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {1, 2, 3, 4});

        mvc.perform(get("/api/v1/log/entries").param("hash", shortHash))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    void getByHashForAbsentHashReturns404() throws Exception {
        // 32 zero bytes, Base64URL-encoded — well-formed but never in the log
        byte[] zeroes = new byte[32];
        String absentHash = Base64.getUrlEncoder().withoutPadding().encodeToString(zeroes);

        mvc.perform(get("/api/v1/log/entries").param("hash", absentHash))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }
}
