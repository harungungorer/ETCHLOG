package dev.hg.etchlog.server.web;

/**
 * Thrown when a requested leaf — looked up by index or by leaf hash — does not exist in the log.
 *
 * <p>Handled by {@link ApiExceptionHandler#handleLeafNotFound} which maps it to a {@code 404 Not
 * Found} problem response.
 */
public class LeafNotFoundException extends RuntimeException {

    /**
     * @param detail a human-readable explanation, e.g. {@code "No leaf exists at index 9999"}.
     */
    public LeafNotFoundException(String detail) {
        super(detail);
    }
}
