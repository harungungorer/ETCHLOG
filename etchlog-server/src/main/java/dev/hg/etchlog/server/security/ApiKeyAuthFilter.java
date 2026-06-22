package dev.hg.etchlog.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Set;
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
 * <p>The comparison is constant-time and iterates the full key set regardless of an early match, so
 * an attacker cannot learn how many leading characters of a guess were correct from response
 * timing.
 *
 * @see SecurityConfig
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    /** Header carrying the appender's API key. */
    public static final String HEADER = "X-Api-Key";

    private static final List<SimpleGrantedAuthority> APPENDER =
            List.of(new SimpleGrantedAuthority("ROLE_APPENDER"));

    /** SHA-256 hex of each valid key, computed once at startup. */
    private final Set<String> allowedKeyHashes;

    public ApiKeyAuthFilter(Set<String> allowedKeyHashes) {
        this.allowedKeyHashes = Set.copyOf(allowedKeyHashes);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String presented = request.getHeader(HEADER);
        if (presented != null && !presented.isBlank() && matches(presented.trim())) {
            var auth = new UsernamePasswordAuthenticationToken("appender", null, APPENDER);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        chain.doFilter(request, response);
    }

    /** Constant-time membership test of the presented key's hash against the allowed set. */
    private boolean matches(String presentedKey) {
        byte[] presentedHash =
                ApiKeyHasher.sha256Hex(presentedKey).getBytes(StandardCharsets.UTF_8);
        boolean found = false;
        for (String stored : allowedKeyHashes) {
            // MessageDigest.isEqual is constant-time for equal-length inputs (SHA-256 hex is always
            // 64 chars), defeating timing attacks. The loop never short-circuits on a match.
            if (MessageDigest.isEqual(presentedHash, stored.getBytes(StandardCharsets.UTF_8))) {
                found = true;
            }
        }
        return found;
    }
}
