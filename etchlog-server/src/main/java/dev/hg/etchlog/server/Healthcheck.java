package dev.hg.etchlog.server;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Self-contained readiness probe invoked as {@code etchlog --healthcheck}.
 *
 * <p>The production runtime image is distroless — no shell, {@code curl}, or {@code wget} — so the
 * orchestrator cannot probe HTTP the usual way. Instead it execs the binary itself with {@code
 * --healthcheck}; this opens a localhost connection to the server's own Actuator readiness endpoint
 * and maps the result to a process exit code (0 = ready, non-zero = not ready). See the Compose
 * healthcheck in {@code docker-compose.yml} and {@code docs/deployment/DOCKER_SETUP.md}.
 *
 * <p>This path must not start Spring: it runs as a short-lived sibling process against the
 * already-running server in the same container.
 */
final class Healthcheck {

    private Healthcheck() {}

    /** Returns a process exit code: 0 when the server reports readiness UP, 1 otherwise. */
    static int run() {
        // The readiness endpoint shares the main server port; honor SERVER_PORT (the env form of
        // server.port) so a non-default port still probes correctly. Management runs on the same
        // port — no separate management.server.port is configured.
        String port = envOrDefault("SERVER_PORT", "8080");
        String url = "http://127.0.0.1:" + port + "/actuator/health/readiness";
        try {
            HttpClient client =
                    HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
            HttpRequest request =
                    HttpRequest.newBuilder(URI.create(url))
                            .timeout(Duration.ofSeconds(3))
                            .GET()
                            .build();
            HttpResponse<String> response =
                    client.send(request, HttpResponse.BodyHandlers.ofString());
            // Anonymous callers see only the top-level {"status":"UP"} (show-details:
            // when-authorized), which is exactly what a liveness/readiness gate needs.
            boolean ready =
                    response.statusCode() == 200 && response.body().contains("\"status\":\"UP\"");
            if (!ready) {
                System.err.println(
                        "healthcheck: "
                                + url
                                + " -> "
                                + response.statusCode()
                                + " "
                                + response.body());
            }
            return ready ? 0 : 1;
        } catch (Exception e) {
            System.err.println("healthcheck: " + url + " unreachable: " + e.getMessage());
            return 1;
        }
    }

    private static String envOrDefault(String name, String fallback) {
        String value = System.getenv(name);
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
