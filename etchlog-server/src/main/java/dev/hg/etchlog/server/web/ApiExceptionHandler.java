package dev.hg.etchlog.server.web;

import dev.hg.etchlog.server.log.DuplicateLeafException;
import dev.hg.etchlog.server.log.InvalidRequestException;
import dev.hg.etchlog.server.log.ProofNotAvailableException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
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

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

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

    /**
     * A request argument was invalid in a way that is safe to report verbatim — its message echoes
     * only client-supplied parameters (see {@link InvalidRequestException}). More specific than the
     * generic {@link IllegalArgumentException} handler below, so Spring routes these here.
     */
    @ExceptionHandler(InvalidRequestException.class)
    public ProblemDetail handleInvalidRequest(
            InvalidRequestException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.BAD_REQUEST, "bad-request", "Bad Request", ex.getMessage(), request);
    }

    /**
     * A non-request {@link IllegalArgumentException} reached the web layer — e.g. an entity
     * invariant or a lower crypto/persistence precondition. Its message may carry internal detail,
     * so a fixed, generic detail is returned instead of echoing it; deliberate client-safe messages
     * use {@link InvalidRequestException} above.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(
            IllegalArgumentException ex, HttpServletRequest request) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "bad-request",
                "Bad Request",
                "The request could not be processed due to an invalid argument.",
                request);
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
     *
     * <p>The detail names the offending parameter and its expected type (both fixed by the
     * controller signature) but deliberately never echoes the client-supplied raw value: reflecting
     * unsanitized input back into the response body is a needless injection vector and leaks
     * nothing useful for diagnosing a type error.
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ProblemDetail handleTypeMismatch(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request) {
        Class<?> required = ex.getRequiredType();
        String detail =
                required != null
                        ? "Parameter '"
                                + ex.getName()
                                + "' must be a valid "
                                + required.getSimpleName()
                                + "."
                        : "Parameter '" + ex.getName() + "' has an invalid value.";
        return problem(HttpStatus.BAD_REQUEST, "bad-request", "Bad Request", detail, request);
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

    /**
     * An internal invariant failed while serving the request — e.g. a materialized Merkle node is
     * missing because the store was modified outside the single-writer sequencer (see {@code
     * LogService}). This is never the normal path; it signals store corruption, not bad input.
     *
     * <p>The exception message carries internal coordinates (tree levels, node indices, row counts)
     * that must not reach a client, so the real cause is logged server-side at {@code ERROR} and
     * the response is a fixed, generic 500. Without this handler the message would surface verbatim
     * in Spring's default 500 problem-detail body.
     */
    @ExceptionHandler(IllegalStateException.class)
    public ProblemDetail handleIllegalState(IllegalStateException ex, HttpServletRequest request) {
        log.error(
                "Internal invariant violated handling {} {}",
                request.getMethod(),
                request.getRequestURI(),
                ex);
        return problem(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "internal-error",
                "Internal Server Error",
                "The request could not be completed due to an internal error.",
                request);
    }

    /**
     * Final safety net for any exception without a more specific handler above. Spring routes an
     * exception to the closest-matching {@code @ExceptionHandler}, so this fires only for the
     * residue: framework MVC exceptions (405, 415, 406, unknown route, …) and genuinely
     * unanticipated failures.
     *
     * <p>Framework MVC exceptions implement {@link ErrorResponse} and already carry the correct
     * status, an {@code application/problem+json} body, and any relevant headers (e.g. {@code
     * Allow} on a 405), so they are passed through untouched rather than masked as a 500 —
     * preserving the shape the {@code spring.mvc.problemdetails} advice used to give them before
     * this catch-all existed. Everything else is a bug, not bad input: the real cause is logged
     * server-side at {@code ERROR} and the client gets a fixed, generic 500 that leaks no internal
     * detail.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleUnexpected(Exception ex, HttpServletRequest request) {
        if (ex instanceof ErrorResponse errorResponse) {
            return new ResponseEntity<>(
                    errorResponse.getBody(),
                    errorResponse.getHeaders(),
                    errorResponse.getStatusCode());
        }
        log.error(
                "Unhandled exception serving {} {}",
                request.getMethod(),
                request.getRequestURI(),
                ex);
        ProblemDetail body =
                problem(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "internal-error",
                        "Internal Server Error",
                        "The request could not be completed due to an internal error.",
                        request);
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
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
