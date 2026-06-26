package dev.hg.etchlog.server.web;

import dev.hg.etchlog.server.log.ClientSafeMessage;

/**
 * Thrown when a requested leaf — looked up by index or by leaf hash — does not exist in the log.
 *
 * <p>Handled by {@link ApiExceptionHandler#handleLeafNotFound} which maps it to a {@code 404 Not
 * Found} problem response.
 *
 * <p>Carries the {@link ClientSafeMessage} marker that authorizes the handler to echo its message
 * verbatim: every call site builds the message from client-supplied input only (the requested index
 * or a fixed not-found string), never internal state.
 */
public class LeafNotFoundException extends RuntimeException implements ClientSafeMessage {

    /**
     * @param detail a human-readable explanation, e.g. {@code "No leaf exists at index 9999"}.
     */
    public LeafNotFoundException(String detail) {
        super(detail);
    }
}
