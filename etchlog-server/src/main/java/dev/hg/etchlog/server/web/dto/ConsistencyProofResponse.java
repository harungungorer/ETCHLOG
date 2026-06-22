package dev.hg.etchlog.server.web.dto;

import java.util.List;

/**
 * JSON view of a consistency proof, matching the public contract {@code { first, second, proof }}.
 *
 * <p>{@code proof} is the minimal set of node hashes proving the size-{@code first} log is an
 * append-only prefix of the size-{@code second} log. Each hash serializes as standard Base64.
 *
 * @param first earlier (smaller) tree size {@code M}
 * @param second later (larger) tree size {@code N}
 * @param proof node hashes reconciling the two roots
 */
public record ConsistencyProofResponse(long first, long second, List<byte[]> proof) {}
