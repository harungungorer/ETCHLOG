package dev.hg.etchlog.server.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configures the springdoc-openapi bean that drives the {@code /v3/api-docs} JSON endpoint and the
 * {@code /swagger-ui.html} interactive UI.
 *
 * <p>Describes the log's public API contract: title, version, a one-line description, and the
 * AGPL-3.0-only license under which the server is released. No security schemes are declared here
 * because the write-authorization API-key scheme is deferred to Milestone 4 — until then {@link
 * SecurityConfig} permits all requests.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    /**
     * Returns the top-level {@link OpenAPI} descriptor for the Etchlog API.
     *
     * <p>springdoc-openapi picks this bean up automatically and merges it with the controller
     * operation metadata scanned from {@code @Operation} / {@code @ApiResponse} annotations.
     */
    @Bean
    public OpenAPI etchlogOpenApi() {
        return new OpenAPI()
                .info(
                        new Info()
                                .title("Etchlog API")
                                .version("v1")
                                .description(
                                        "Self-hostable RFC 6962 transparency log: append records,"
                                                + " verify inclusion and consistency proofs without"
                                                + " trusting the operator.")
                                .license(
                                        new License()
                                                .name("AGPL-3.0-only")
                                                .url(
                                                        "https://www.gnu.org/licenses/agpl-3.0.html")));
    }
}
