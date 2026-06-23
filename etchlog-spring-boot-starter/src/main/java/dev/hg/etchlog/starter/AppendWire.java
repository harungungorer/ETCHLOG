package dev.hg.etchlog.starter;

/**
 * Internal wire DTO for deserializing the append response from the server.
 *
 * <p>Maps the server JSON:
 *
 * <pre>{@code
 * {"leaf_index": 0, "sth": {"tree_size": 1, "root_hash": "...", "timestamp": 123, "ed25519_signature": "..."}}
 * }</pre>
 */
record AppendWire(long leafIndex, SthWire sth) {

    /** Convert to the public {@link AppendResult}. */
    AppendResult toAppendResult() {
        return new AppendResult(leafIndex, sth.toSignedTreeHead());
    }
}
