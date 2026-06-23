package dev.hg.etchlog.server.demo;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Without the {@code demo} profile, the tamper endpoint must NOT be reachable: the {@code
 * @Profile("demo")} controller bean is absent and the fail-closed main security chain {@code
 * denyAll}s the path. This guards against ever exposing the destructive demo endpoint in
 * production.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DemoTamperDisabledWebTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-nodemo.db"));
    }

    @Autowired MockMvc mvc;

    @Test
    void tamperIsBlockedWhenDemoProfileInactive() throws Exception {
        // denyAll (anonymous) renders as a 4xx client error — never reaching a controller.
        mvc.perform(post("/api/v1/_demo/tamper/{index}", 0))
                .andExpect(status().is4xxClientError());
    }
}
