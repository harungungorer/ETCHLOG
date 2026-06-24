package dev.hg.etchlog.server.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Verifies the operational endpoints exposed by the server: the Spring Boot Actuator health probe
 * ({@code /actuator/health}) and the springdoc-openapi JSON descriptor ({@code /v3/api-docs}) plus
 * the Swagger UI ({@code /swagger-ui/index.html}).
 *
 * <p>Uses the same full-stack {@link SpringBootTest} setup as {@link LogControllerTest} — real JPA,
 * Flyway, and the security placeholder — booted against a throwaway SQLite file so tests are
 * hermetic and leave no filesystem state behind.
 */
@SpringBootTest
@AutoConfigureMockMvc
// Spring Boot disables metrics export (and thus the Prometheus scrape endpoint) in tests by
// default; this re-enables it so the scrape endpoint is registered and assertable here, matching
// the production runtime where export is always on.
@AutoConfigureObservability
class OperationalEndpointsTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url", () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-ops.db"));
    }

    @Autowired MockMvc mvc;

    /** Actuator health endpoint must return HTTP 200 with {@code status: "UP"}. */
    @Test
    void actuatorHealthReturnsUp() throws Exception {
        mvc.perform(get("/actuator/health").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    /**
     * The actuator discovery (links) endpoint is explicitly public, so monitoring probes that hit
     * {@code /actuator} get the link index rather than a confusing 403 from the fail-closed
     * default.
     */
    @Test
    void actuatorRootIsAccessible() throws Exception {
        mvc.perform(get("/actuator").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$._links").exists());
    }

    /**
     * OpenAPI JSON descriptor must be reachable at the springdoc default path and must contain the
     * {@code openapi} version field and the configured API title.
     */
    @Test
    void openApiDocsAreServed() throws Exception {
        mvc.perform(get("/v3/api-docs").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openapi").isString())
                .andExpect(jsonPath("$.info.title").value("Etchlog API"));
    }

    /**
     * Swagger UI must be reachable at the path springdoc serves the bundled HTML page. (The legacy
     * {@code /swagger-ui.html} path merely redirects here.)
     */
    @Test
    void swaggerUiIsServed() throws Exception {
        mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isOk());
    }

    /**
     * The Prometheus scrape endpoint must be public (no API key) and must expose Etchlog's custom
     * domain meters. The {@code etchlog_tree_size} gauge is registered at startup, so it is present
     * in the scrape even before the first append, alongside the documented common {@code
     * application="etchlog"} tag.
     */
    @Test
    void prometheusEndpointServesEtchlogMetrics() throws Exception {
        String body =
                mvc.perform(get("/actuator/prometheus"))
                        .andExpect(status().isOk())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();

        // Assert the exact documented metric names (MONITORING_LOGGING.md). The trailing `{` (the
        // tag block) pins the full name, so a base-unit suffix regression
        // (etchlog_tree_size_leaves)
        // would fail here rather than slip past a loose substring match — the documented alert
        // PromQL references etchlog_tree_size, so the name is a contract.
        assertThat(body).contains("etchlog_tree_size{");
        assertThat(body).doesNotContain("etchlog_tree_size_leaves");
        assertThat(body).contains("etchlog_tree_head_timestamp_seconds{");
        assertThat(body).contains("etchlog_append_latency_seconds");
        assertThat(body).contains("application=\"etchlog\"");
    }
}
