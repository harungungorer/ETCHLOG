package dev.hg.etchlog.server.web;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

/**
 * Builds the API's standard {@code application/problem+json} body (RFC 9457 via Spring's {@link
 * ProblemDetail}), augmented with the contract's stable {@code type} URI and {@code timestamp}
 * (epoch ms). Shared so every advice — the always-on {@link ApiExceptionHandler} and the
 * demo-profile handler — renders byte-identical problems.
 */
public final class ProblemDetails {

    /** Stable {@code type} URI prefix; each problem class appends its slug. */
    public static final String PROBLEM_BASE = "https://etchlog.dev/problems/";

    private ProblemDetails() {}

    public static ProblemDetail of(
            HttpStatus status,
            String typeSlug,
            String title,
            String detail,
            HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setType(URI.create(PROBLEM_BASE + typeSlug));
        pd.setTitle(title);
        pd.setInstance(URI.create(request.getRequestURI()));
        pd.setProperty("timestamp", System.currentTimeMillis());
        return pd;
    }
}
