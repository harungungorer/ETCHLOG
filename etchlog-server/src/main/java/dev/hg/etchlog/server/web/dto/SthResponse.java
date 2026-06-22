package dev.hg.etchlog.server.web.dto;

import dev.hg.etchlog.core.sth.SignedTreeHead;

/**
 * JSON view of a Signed Tree Head, matching the public contract {@code { tree_size, root_hash,
 * timestamp, ed25519_signature }}.
 *
 * <p>The byte fields serialize as standard Base64 (Jackson's default {@code byte[]} encoding) and
 * the field names render in snake_case via the application-wide naming strategy. {@code timestamp}
 * is epoch milliseconds.
 *
 * @param treeSize number of leaves committed by this STH
 * @param rootHash RFC 6962 root over the first {@code treeSize} leaves
 * @param timestamp epoch-millisecond instant the STH was signed
 * @param ed25519Signature Ed25519 signature over the canonical STH bytes
 */
public record SthResponse(long treeSize, byte[] rootHash, long timestamp, byte[] ed25519Signature) {

    /** Projects a core {@link SignedTreeHead} into its public JSON shape. */
    public static SthResponse from(SignedTreeHead sth) {
        return new SthResponse(sth.treeSize(), sth.rootHash(), sth.timestamp(), sth.signature());
    }
}
