package dev.hg.etchlog.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates append requests by API key. Stateless — no session is created. The filter only ever
 * <em>grants</em> authority: when a valid {@code X-Api-Key} is presented it populates the security
 * context with {@code ROLE_APPENDER}. When the key is missing or invalid it does nothing and lets
 * Spring Security's authorization rules reject the request (the configured entry point renders a
 * {@code 401}).
 *
 * <p>Validity is decided by the injected {@link ApiKeyAuthenticator} — the database-backed
 * authenticator looks the presented key's SHA-256 up among the <em>active</em> {@code api_keys}
 * rows, so a revoked key is rejected immediately. The filter holds no key material itself.
 *
 * @see SecurityConfig
 * @see ApiKeyAuthenticator
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    /** Header carrying the appender's API key. */
    public static final String HEADER = "X-Api-Key";

    private static final List<SimpleGrantedAuthority> APPENDER =
            List.of(new SimpleGrantedAuthority("ROLE_APPENDER"));

    private final ApiKeyAuthenticator authenticator;

    public ApiKeyAuthFilter(ApiKeyAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String presented = request.getHeader(HEADER);
        if (presented != null
                && !presented.isBlank()
                && authenticator.isValidAppenderKey(presented.trim())) {
            var auth = new UsernamePasswordAuthenticationToken("appender", null, APPENDER);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        chain.doFilter(request, response);
    }
}
