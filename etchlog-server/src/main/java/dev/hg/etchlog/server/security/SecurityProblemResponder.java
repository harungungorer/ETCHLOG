package dev.hg.etchlog.server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.hg.etchlog.server.web.ProblemDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Renders security failures in the same RFC 9457 {@code application/problem+json} shape the rest of
 * the API uses (see {@code ApiExceptionHandler}), so a client gets one consistent error contract
 * whether a request fails validation or authentication.
 *
 * <ul>
 *   <li>As an {@link AuthenticationEntryPoint}: a missing/invalid {@code X-Api-Key} on a protected
 *       route yields {@code 401 Unauthorized}.
 *   <li>As an {@link AccessDeniedHandler}: an authenticated principal lacking {@code ROLE_APPENDER}
 *       yields {@code 403 Forbidden}.
 * </ul>
 */
public class SecurityProblemResponder implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final ObjectMapper json;

    public SecurityProblemResponder(ObjectMapper json) {
        this.json = json;
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException)
            throws IOException {
        write(
                response,
                request,
                HttpStatus.UNAUTHORIZED,
                "unauthorized",
                "Unauthorized",
                "A valid X-Api-Key header is required to append to the log.");
    }

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException)
            throws IOException {
        write(
                response,
                request,
                HttpStatus.FORBIDDEN,
                "forbidden",
                "Forbidden",
                "The presented credential is not permitted to perform this action.");
    }

    private void write(
            HttpServletResponse response,
            HttpServletRequest request,
            HttpStatus status,
            String typeSlug,
            String title,
            String detail)
            throws IOException {
        ProblemDetail pd = ProblemDetails.of(status, typeSlug, title, detail, request);

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        json.writeValue(response.getWriter(), pd);
    }
}
