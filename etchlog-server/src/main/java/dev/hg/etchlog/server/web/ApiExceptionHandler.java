package dev.hg.etchlog.server.web;

import dev.hg.etchlog.server.log.DuplicateLeafException;
import dev.hg.etchlog.server.log.ProofNotAvailableException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/**
 * Translates failures into the API's standard JSON {@code application/problem+json} shape (RFC 9457
 * via Spring's {@link ProblemDetail}), augmented with the contract's {@code timestamp} (epoch ms)
 * and a stable {@code type} URI per problem class.
 *
 * <p>Authentication/authorization failures (401/403) are produced by the security layer; not-found
 * and proof-consistency errors (404/409) for the read and proof endpoints are added alongside those
 * endpoints. A {@code 500} is never allowed to masquerade as a degraded proof — see {@code
 * docs/api/API_DOCUMENTATION.md}.
 *
 * <p>Ordered ahead of Spring's built-in problem-details advice ({@code spring.mvc.problemdetails})
 * so these handlers — which add the contract's {@code timestamp}/{@code type} — win for the
 * exceptions listed here, while framework exceptions we do not handle (405, 415, …) still render as
 * {@code application/problem+json}.
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ApiExceptionHandler {

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

    /**
     * A leaf requested by index or hash was not found in the log.
     *
     * @see LeafNotFoundException
     */
    @ExceptionHandler(LeafNotFoundException.class)
    public ProblemDetail handleLeafNotFound(LeafNotFoundException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.NOT_FOUND, "leaf-not-found", "Leaf Not Found", ex.getMessage(), request);
    }

    /**
     * A path variable or query parameter could not be converted to its declared type — e.g. a
     * non-numeric {@code {index}} or {@code tree_size} yields a 400 rather than a 500.
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ProblemDetail handleTypeMismatch(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "bad-request",
                "Bad Request",
                "Parameter '" + ex.getName() + "' has an invalid value: " + ex.getValue(),
                request);
    }

    /** A required query parameter was absent (e.g. {@code hash}, {@code leaf_index}). */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ProblemDetail handleMissingParam(
            MissingServletRequestParameterException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "bad-request",
                "Bad Request",
                "Required parameter '" + ex.getParameterName() + "' is missing.",
                request);
    }

    /** A proof was requested against a tree size the log has not yet reached. */
    @ExceptionHandler(ProofNotAvailableException.class)
    public ProblemDetail handleProofNotAvailable(
            ProofNotAvailableException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.NOT_FOUND,
                "tree-size-out-of-range",
                "Tree Size Out Of Range",
                ex.getMessage(),
                request);
    }

    private static ProblemDetail problem(
            HttpStatus status,
            String typeSlug,
            String title,
            String detail,
            HttpServletRequest request) {
        return ProblemDetails.of(status, typeSlug, title, detail, request);
    }
}
