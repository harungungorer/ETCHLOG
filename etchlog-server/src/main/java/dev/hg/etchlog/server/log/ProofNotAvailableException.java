package dev.hg.etchlog.server.log;

/**
 * Thrown when a proof is requested against a tree size the log has not yet reached (i.e. {@code
 * tree_size}/{@code second} exceeds the current log size, so no STH covers it).
 *
 * <p>The web layer maps this to {@code 404 Not Found}. Etchlog never returns a partially valid
 * proof: if it cannot be produced honestly for the requested size, the request fails rather than
 * returning a degraded result.
 */
public class ProofNotAvailableException extends RuntimeException {

    public ProofNotAvailableException(String detail) {
        super(detail);
    }
}
