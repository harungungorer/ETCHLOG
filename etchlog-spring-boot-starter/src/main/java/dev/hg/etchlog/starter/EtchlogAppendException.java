package dev.hg.etchlog.starter;

/**
 * Thrown when an append to the log server fails after exhausting all retry attempts and {@code
 * etchlog.append.fail-open} is {@code false} (the default).
 *
 * <p>Inside a {@code @Transactional} method this causes the business transaction to roll back,
 * ensuring no business event exists without a corresponding log entry.
 */
public class EtchlogAppendException extends RuntimeException {

    /**
     * Constructs an exception with a detail message and a causal exception.
     *
     * @param message description of the failure
     * @param cause the underlying cause
     */
    public EtchlogAppendException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs an exception with a detail message and no cause.
     *
     * @param message description of the failure
     */
    public EtchlogAppendException(String message) {
        super(message);
    }
}
