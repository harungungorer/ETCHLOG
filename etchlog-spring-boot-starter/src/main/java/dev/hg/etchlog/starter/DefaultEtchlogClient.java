package dev.hg.etchlog.starter;

import dev.hg.etchlog.core.sth.SignedTreeHead;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * Default {@link EtchlogClient} implementation backed by a Spring {@link RestClient}.
 *
 * <p>Retries transient (IO / 5xx) failures up to {@code etchlog.append.retry.max-attempts} times
 * with a fixed backoff. On final failure either throws {@link EtchlogAppendException} (fail-closed,
 * the default) or returns a sentinel {@link AppendResult} (fail-open).
 */
public class DefaultEtchlogClient implements EtchlogClient {

    private static final Logger log = LoggerFactory.getLogger(DefaultEtchlogClient.class);

    private final RestClient restClient;
    private final EtchlogProperties props;
    private final ExecutorService executor;

    /**
     * Constructs a client using the provided pre-configured {@link RestClient} and properties.
     *
     * @param restClient a pre-configured RestClient (base URL, headers, converters already set)
     * @param props bound configuration properties
     */
    public DefaultEtchlogClient(RestClient restClient, EtchlogProperties props) {
        this.restClient = restClient;
        this.props = props;
        // A small bounded pool for async appends. Daemon threads so a lingering pool never blocks
        // JVM shutdown; threads are created lazily, so SYNC-only callers pay nothing.
        this.executor =
                Executors.newFixedThreadPool(
                        Runtime.getRuntime().availableProcessors() * 2, daemonThreadFactory());
    }

    private static ThreadFactory daemonThreadFactory() {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread t = new Thread(runnable, "etchlog-append-" + counter.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    @Override
    public AppendResult append(byte[] data) {
        int maxAttempts = props.getAppend().getRetry().getMaxAttempts();
        long backoffMs = props.getAppend().getRetry().getBackoff().toMillis();
        Exception lastException = null;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                AppendWire wire =
                        restClient
                                .post()
                                .uri("/api/v1/log/entries")
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(new AppendRequestWire(data))
                                .retrieve()
                                .body(AppendWire.class);
                if (wire == null) {
                    throw new EtchlogAppendException("Server returned empty body on append");
                }
                return wire.toAppendResult();
            } catch (RestClientResponseException e) {
                // 4xx are non-transient (invalid/missing API key, duplicate leaf, bad request);
                // retrying cannot help, so fail fast rather than burning attempts and backoff.
                if (e.getStatusCode().is4xxClientError()) {
                    throw new EtchlogAppendException(
                            "Append rejected by server with status " + e.getStatusCode().value(),
                            e);
                }
                lastException = e; // 5xx — transient server error, eligible for retry
            } catch (ResourceAccessException e) {
                lastException = e; // IO / connect / read-timeout — transient, eligible for retry
            }
            log.warn(
                    "Append attempt {}/{} failed: {}",
                    attempt,
                    maxAttempts,
                    lastException.getMessage());
            if (attempt < maxAttempts) {
                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException ie) {
                    // Restore the interrupt status and keep the cause so the fail-closed throw
                    // below carries it (rather than a null cause when interrupted on attempt 1).
                    Thread.currentThread().interrupt();
                    lastException = ie;
                    break;
                }
            }
        }

        // All attempts exhausted.
        if (props.getAppend().isFailOpen()) {
            log.warn(
                    "Append failed after {} attempts; fail-open is true — returning sentinel result. "
                            + "The record was NOT etched in the log.",
                    maxAttempts,
                    lastException);
            /*
             * Sentinel result: leafIndex -1 signals a swallowed failure.
             * Core's SignedTreeHead requires a 32-byte rootHash and a 64-byte (Ed25519-length)
             * signature; we satisfy both with zero-filled arrays. The all-zero signature is a
             * valid length but verifies against no key, so a caller that mistakes the sentinel for
             * a real STH still fails closed at verification rather than trusting it.
             */
            return new AppendResult(
                    -1L,
                    new SignedTreeHead(
                            0L, new byte[32], 0L, new byte[SignedTreeHead.SIGNATURE_LENGTH]));
        }

        throw new EtchlogAppendException(
                "Append failed after " + maxAttempts + " attempt(s)", lastException);
    }

    @Override
    public CompletableFuture<AppendResult> appendAsync(byte[] data) {
        return CompletableFuture.supplyAsync(() -> append(data), executor);
    }

    @Override
    public InclusionProofResponse inclusionProof(long leafIndex, long treeSize) {
        InclusionWire wire =
                restClient
                        .get()
                        .uri(
                                uriBuilder ->
                                        uriBuilder
                                                .path("/api/v1/log/proofs/inclusion")
                                                .queryParam("leaf_index", leafIndex)
                                                .queryParam("tree_size", treeSize)
                                                .build())
                        .retrieve()
                        .body(InclusionWire.class);
        if (wire == null) {
            throw new EtchlogAppendException("Server returned empty body for inclusion proof");
        }
        return wire.toInclusionProofResponse();
    }

    @Override
    public SignedTreeHead signedTreeHead() {
        SthWire wire = restClient.get().uri("/api/v1/log/sth").retrieve().body(SthWire.class);
        if (wire == null) {
            throw new EtchlogAppendException("Server returned empty body for STH");
        }
        return wire.toSignedTreeHead();
    }
}
