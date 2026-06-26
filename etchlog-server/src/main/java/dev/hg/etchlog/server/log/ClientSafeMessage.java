package dev.hg.etchlog.server.log;

/**
 * Marks an exception whose {@linkplain Throwable#getMessage() message} is deliberately safe to
 * surface verbatim to API clients: it echoes only client-supplied request input (an index, a hash,
 * a tree size, a field name) and never internal state (row counts, node coordinates, the current
 * log size, datasource strings, or any other implementation detail).
 *
 * <p>{@code ApiExceptionHandler} forwards {@code getMessage()} into the problem {@code detail} only
 * for exceptions carrying this marker; every other exception receives a fixed, generic detail. That
 * makes the set of client-visible error messages a curated, reviewable allow-list rather than an
 * incidental property of each throw site — the defence-in-depth boundary the post-M8 audit
 * established for {@link InvalidRequestException} (400s), now shared across the 404 paths
 * ({@link ProofNotAvailableException}, {@code LeafNotFoundException}) as well.
 *
 * <p>Implementing this interface is a contract, not a convenience: every {@code new} call site of a
 * carrying type must be reviewed to pass only client-supplied input into the message. A type that
 * cannot make that guarantee must not implement it, so its message stays behind a generic detail.
 *
 * <p>The marker lives in the {@code log} layer (the lower layer that {@code web} already depends on)
 * so both the service-thrown exceptions here and the controller-thrown {@code LeafNotFoundException}
 * in {@code web} can carry it without inverting the package layering.
 */
public interface ClientSafeMessage {}
