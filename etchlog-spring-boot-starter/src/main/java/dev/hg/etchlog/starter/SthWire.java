package dev.hg.etchlog.starter;

import dev.hg.etchlog.core.sth.SignedTreeHead;

/**
 * Internal wire DTO for deserializing the server's STH JSON.
 *
 * <p>The server uses snake_case field names ({@code tree_size}, {@code root_hash}, {@code
 * ed25519_signature}). With a snake_case {@link com.fasterxml.jackson.databind.ObjectMapper}, the
 * camelCase field names here map automatically.
 *
 * <p>Use {@link #toSignedTreeHead()} to convert to the public core type.
 */
record SthWire(long treeSize, byte[] rootHash, long timestamp, byte[] ed25519Signature) {

    /** Convert to the public {@link SignedTreeHead} type from {@code etchlog-core}. */
    SignedTreeHead toSignedTreeHead() {
        return new SignedTreeHead(treeSize, rootHash, timestamp, ed25519Signature);
    }
}
