package dev.hg.etchlog.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Baseline HTTP security for the API.
 *
 * <p><strong>Milestone 3 placeholder:</strong> because {@code spring-boot-starter-security} is on
 * the classpath, the default filter chain would lock down every endpoint. The log's design is the
 * opposite — reads and proofs are <em>public</em> so any auditor can verify without trust, and only
 * appends are authenticated. Until the API-key write authorization lands in Milestone 4, this chain
 * permits all requests so the M3 endpoints are reachable. CSRF is disabled because the API is a
 * stateless JSON service authenticated (later) by an {@code X-Api-Key} header, not a session
 * cookie.
 *
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable());
        return http.build();
    }
}
