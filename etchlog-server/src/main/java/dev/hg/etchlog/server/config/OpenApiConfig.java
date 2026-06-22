package dev.hg.etchlog.server.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configures the springdoc-openapi bean that drives the {@code /v3/api-docs} JSON endpoint and the
 * {@code /swagger-ui.html} interactive UI.
 *
 * <p>Describes the log's public API contract: title, version, a one-line description, and the
 * AGPL-3.0-only license under which the server is released. It also declares the {@code ApiKeyAuth}
 * security scheme (an {@code X-Api-Key} request header); the append operation references it via a
 * {@code @SecurityRequirement} so Swagger UI prompts for the key, while reads/proofs stay public.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    /**
     * OpenAPI components name of the appender API-key scheme; referenced by the append operation.
     */
    public static final String API_KEY_SCHEME = "ApiKeyAuth";

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
                                                .url("https://www.gnu.org/licenses/agpl-3.0.html")))
                .components(
                        new Components()
                                .addSecuritySchemes(
                                        API_KEY_SCHEME,
                                        new SecurityScheme()
                                                .type(SecurityScheme.Type.APIKEY)
                                                .in(SecurityScheme.In.HEADER)
                                                .name("X-Api-Key")
                                                .description(
                                                        "Appender API key. Required only on POST"
                                                                + " /api/v1/log/entries; reads and"
                                                                + " proofs are public.")));
    }
}
