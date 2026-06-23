package dev.hg.etchlog.server.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * DEMO-ONLY security: opens the {@code /api/v1/_demo/**} tamper endpoint without an API key.
 *
 * <p>Active only under the {@code demo} profile. This chain has higher precedence
 * ({@code @Order(1)} vs. the main chain's {@code @Order(2)}) and a {@code securityMatcher} scoped
 * to {@code _demo}, so it handles only those requests; all other paths still flow through the
 * fail-closed main chain. When the {@code demo} profile is inactive this bean does not exist, and
 * the main chain's {@code denyAll} blocks {@code _demo} requests (which have no controller to reach
 * anyway).
 *
 * @see dev.hg.etchlog.server.security.SecurityConfig
 */
@Configuration
@Profile("demo")
public class DemoSecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain demoFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/v1/_demo/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
