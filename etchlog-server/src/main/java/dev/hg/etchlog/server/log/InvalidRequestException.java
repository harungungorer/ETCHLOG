package dev.hg.etchlog.server.log;

/**
 * A bad-request signal whose {@linkplain #getMessage() message} is deliberately safe to surface to
 * API clients: it echoes only client-supplied request parameters (an index, a tree size, a field
 * name), never internal state. {@code ApiExceptionHandler} forwards this message verbatim as the
 * {@code 400} problem {@code detail}.
 *
 * <p>A plain {@link IllegalArgumentException} — which may originate in an entity invariant or a
 * lower crypto/persistence layer and carry implementation detail — is instead mapped to a generic
 * {@code 400} detail, so internal messages can never leak through the error contract. This is the
 * defence-in-depth boundary the post-M8 audit asked for: the set of client-visible 400 messages is
 * exactly the set of {@code InvalidRequestException} call sites, all of which are reviewed to echo
 * only request input.
 *
 * <p>Extends {@link IllegalArgumentException} so existing {@code catch} chains and the validation
 * contract continue to treat it as an illegal argument; it lives beside the other request-mapped
 * log exceptions ({@link DuplicateLeafException}, {@link ProofNotAvailableException}). It carries
 * the {@link ClientSafeMessage} marker that authorizes the handler to echo its message verbatim.
 */
public class InvalidRequestException extends IllegalArgumentException implements ClientSafeMessage {

    public InvalidRequestException(String message) {
        super(message);
    }
}
