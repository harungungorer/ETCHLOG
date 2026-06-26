package dev.hg.etchlog.server.log;

/**
 * Thrown when a proof is requested against a tree size the log has not yet reached (i.e. {@code
 * tree_size}/{@code second} exceeds the current log size, so no STH covers it).
 *
 * <p>The web layer maps this to {@code 404 Not Found}. Etchlog never returns a partially valid
 * proof: if it cannot be produced honestly for the requested size, the request fails rather than
 * returning a degraded result.
 *
 * <p>Carries the {@link ClientSafeMessage} marker: its message echoes only the client-supplied
 * requested size and never the current log size (which would let a 404 probe read the exact tree
 * size out of the error body).
 */
public class ProofNotAvailableException extends RuntimeException implements ClientSafeMessage {

    public ProofNotAvailableException(String detail) {
        super(detail);
    }
}
