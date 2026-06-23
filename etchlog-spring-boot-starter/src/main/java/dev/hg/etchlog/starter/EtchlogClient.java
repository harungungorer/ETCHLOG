package dev.hg.etchlog.starter;

import dev.hg.etchlog.core.sth.SignedTreeHead;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

/**
 * Client for appending records to and querying an {@code etchlog-server}.
 *
 * <p>Inject this bean in any Spring component after adding the starter dependency and setting
 * {@code etchlog.base-url}.
 *
 * <p>Example:
 *
 * <pre>{@code
 * @Autowired EtchlogClient etchlog;
 *
 * AppendResult result = etchlog.append("my-payload");
 * long leafIndex = result.leafIndex();   // store this with your domain entity
 * }</pre>
 */
public interface EtchlogClient {

    /**
     * Append raw bytes synchronously; blocks until the server acknowledges and returns the assigned
     * leaf index and the resulting Signed Tree Head.
     *
     * @param data the record to append (must not be null)
     * @return the leaf index and STH produced by this append
     * @throws EtchlogAppendException if the append fails and {@code etchlog.append.fail-open=false}
     */
    AppendResult append(byte[] data);

    /**
     * Convenience overload: append a UTF-8 string.
     *
     * @param data the record to append encoded as UTF-8
     * @return the leaf index and STH produced by this append
     * @throws EtchlogAppendException if the append fails and {@code etchlog.append.fail-open=false}
     */
    default AppendResult append(String data) {
        return append(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Non-blocking append; schedules the append on a bounded executor and returns immediately.
     *
     * <p>Typically used when {@code etchlog.append.mode=ASYNC}.
     *
     * @param data the record to append (must not be null)
     * @return a future that completes with the append result, or fails with {@link
     *     EtchlogAppendException}
     */
    CompletableFuture<AppendResult> appendAsync(byte[] data);

    /**
     * Fetch an inclusion proof for a previously-appended leaf.
     *
     * @param leafIndex the zero-based index returned by a prior {@link #append}
     * @param treeSize the log size to compute the proof against
     * @return the sibling hashes proving the leaf is in the tree
     */
    InclusionProofResponse inclusionProof(long leafIndex, long treeSize);

    /**
     * Fetch the current Signed Tree Head from the log server.
     *
     * @return the latest STH
     */
    SignedTreeHead signedTreeHead();
}
