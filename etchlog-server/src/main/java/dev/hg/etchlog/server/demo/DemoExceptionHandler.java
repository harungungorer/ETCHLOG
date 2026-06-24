package dev.hg.etchlog.server.demo;

import dev.hg.etchlog.server.web.ProblemDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Renders demo-only failures in the same {@code application/problem+json} shape as the rest of the
 * API (stable {@code type} URI + {@code timestamp}), instead of letting the framework's default
 * {@code @ResponseStatus} handling emit a body that lacks those contract fields. Loaded only under
 * the {@code demo} profile, alongside the demo tamper endpoint it serves.
 *
 * @see dev.hg.etchlog.server.web.ApiExceptionHandler
 */
@RestControllerAdvice
@Profile("demo")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class DemoExceptionHandler {

    /** The demo tamper endpoint targeted a leaf index that does not exist → 404. */
    @ExceptionHandler(DemoLeafNotFoundException.class)
    public ProblemDetail handleDemoLeafNotFound(
            DemoLeafNotFoundException ex, HttpServletRequest request) {
        return ProblemDetails.of(
                HttpStatus.NOT_FOUND, "leaf-not-found", "Leaf Not Found", ex.getMessage(), request);
    }
}
