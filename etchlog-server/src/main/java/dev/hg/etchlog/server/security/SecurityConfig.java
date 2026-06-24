package dev.hg.etchlog.server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.DispatcherType;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * HTTP security for the log. There is exactly one privilege boundary: the append endpoint.
 *
 * <ul>
 *   <li><strong>Write</strong> ({@code POST /api/v1/log/entries}) requires {@code ROLE_APPENDER},
 *       granted by {@link ApiKeyAuthFilter} for a valid {@code X-Api-Key}.
 *   <li><strong>Read / proofs / STH</strong> are fully public — that publicness <em>is</em> the
 *       transparency property: an auditor must be able to verify without any credential the
 *       operator could revoke.
 *   <li>Operational and docs endpoints (health, prometheus, OpenAPI, Swagger UI) are public.
 *   <li>Everything else is {@code denyAll()} — fail-closed, so adding a new endpoint forces a
 *       deliberate public/appender decision.
 * </ul>
 *
 * <p>The API is stateless: no sessions, no CSRF tokens, no HTTP-basic/form login. Authentication
 * failures render as {@code application/problem+json} via {@link SecurityProblemResponder}.
 *
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
@Configuration
@EnableConfigurationProperties(ApiKeyProperties.class)
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    @Order(2)
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            ApiKeyProperties props,
            ApiKeyAuthenticator authenticator,
            ObjectMapper json)
            throws Exception {
        // Fail-closed validation only: ensures at least one key is configured to seed (and drives
        // the demo warning). Runtime authentication is against the api_keys table via
        // `authenticator`.
        Set<String> hashes = props.resolvedKeyHashes();
        if (props.usesDemoKey()) {
            log.warn(
                    """
                    ════════════════════════════════════════════════════════════════════
                    Etchlog append API key is the built-in DEMO key (etchlog-demo-key-change-me).
                    This key is public and well-known: anyone can append to this log.
                    Set ETCHLOG_SECURITY_API_KEYS to a real secret before exposing the server.
                    ════════════════════════════════════════════════════════════════════""");
        }
        log.info("Appender authorization enabled with {} configured API key(s).", hashes.size());

        var responder = new SecurityProblemResponder(json);

        http.csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        auth ->
                                auth
                                        // Let internal FORWARD/ERROR dispatches through; security
                                        // is
                                        // applied to the originating request, not the error render.
                                        .dispatcherTypeMatchers(
                                                DispatcherType.FORWARD, DispatcherType.ERROR)
                                        .permitAll()
                                        // WRITE: appends require the appender role.
                                        .requestMatchers(HttpMethod.POST, "/api/v1/log/entries")
                                        .hasRole("APPENDER")
                                        // READ / PROOFS / STH: public (the transparency property).
                                        .requestMatchers(HttpMethod.GET, "/api/v1/log/**")
                                        .permitAll()
                                        // Ops & docs.
                                        .requestMatchers(
                                                "/actuator",
                                                "/actuator/health",
                                                "/actuator/health/**",
                                                "/actuator/info",
                                                "/actuator/prometheus",
                                                "/v3/api-docs",
                                                "/v3/api-docs/**",
                                                "/v3/api-docs.yaml",
                                                "/swagger-ui.html",
                                                "/swagger-ui/**")
                                        .permitAll()
                                        // Fail-closed: anything not listed above is denied.
                                        .anyRequest()
                                        .denyAll())
                .exceptionHandling(
                        ex -> ex.authenticationEntryPoint(responder).accessDeniedHandler(responder))
                .addFilterBefore(
                        new ApiKeyAuthFilter(authenticator),
                        UsernamePasswordAuthenticationFilter.class)
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable());

        return http.build();
    }
}
