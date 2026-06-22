package dev.hg.etchlog.server.web;

import dev.hg.etchlog.server.log.DuplicateLeafException;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates failures into the API's standard JSON {@code application/problem+json} shape (RFC 9457
 * via Spring's {@link ProblemDetail}), augmented with the contract's {@code timestamp} (epoch ms)
 * and a stable {@code type} URI per problem class.
 *
 * <p>Authentication/authorization failures (401/403) are produced by the security layer; not-found
 * and proof-consistency errors (404/409) for the read and proof endpoints are added alongside those
 * endpoints. A {@code 500} is never allowed to masquerade as a degraded proof — see {@code
 * docs/api/API_DOCUMENTATION.md}.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final String PROBLEM_BASE = "https://etchlog.dev/problems/";

    /** Bean-validation failure on a request body (e.g. missing/empty {@code leaf_data}). */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        String detail =
                ex.getBindingResult().getFieldErrors().stream()
                        .findFirst()
                        .map(fe -> fe.getDefaultMessage())
                        .orElse("Request validation failed.");
        return problem(
                HttpStatus.BAD_REQUEST, "validation-failed", "Validation Failed", detail, request);
    }

    /** Malformed JSON or an undecodable Base64 field. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ProblemDetail handleUnreadable(
            HttpMessageNotReadableException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "malformed-request",
                "Malformed Request",
                "Request body is not valid JSON or a field is not valid Base64.",
                request);
    }

    /** A core/service precondition rejected the input (defensive 400). */
    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(
            IllegalArgumentException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.BAD_REQUEST, "bad-request", "Bad Request", ex.getMessage(), request);
    }

    /** The record's leaf hash is already in the log ({@code UNIQUE (leaf_hash)}). */
    @ExceptionHandler(DuplicateLeafException.class)
    public ProblemDetail handleDuplicate(DuplicateLeafException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.CONFLICT,
                "duplicate-leaf",
                "Duplicate Leaf",
                "This record is already present in the log.",
                request);
    }

    private static ProblemDetail problem(
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
