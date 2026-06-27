package dev.hg.etchlog.server.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;
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
 * Verifies that the {@link dev.hg.etchlog.server.health.SigningKeyHealthIndicator} is wired into
 * Spring Boot Actuator as the documented {@code signingKey} component — surfacing the algorithm and
 * public-key fingerprint at {@code /actuator/health}, and participating in the {@code readiness}
 * group ({@code /actuator/health/readiness}).
 *
 * <p>Component details are normally gated by {@code show-details: when-authorized}; this test
 * forces {@code show-details=always} so the anonymous MockMvc request can assert the detail shape
 * the ops docs promise.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SigningKeyHealthWebTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-signingkey-health.db"));
        // Surface component details to the anonymous probe so the detail contract is assertable.
        registry.add("management.endpoint.health.show-details", () -> "always");
    }

    @Autowired MockMvc mvc;

    @Test
    void signingKeyComponentReportsUpWithFingerprint() throws Exception {
        mvc.perform(get("/actuator/health").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components.signingKey.status").value("UP"))
                .andExpect(jsonPath("$.components.signingKey.details.algorithm").value("Ed25519"))
                .andExpect(
                        jsonPath("$.components.signingKey.details.keyFingerprint")
                                .value(org.hamcrest.Matchers.matchesPattern("[0-9a-f]{64}")));
    }

    @Test
    void signingKeyIsPartOfReadinessGroup() throws Exception {
        mvc.perform(get("/actuator/health/readiness").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components.signingKey.status").value("UP"));
    }
}
