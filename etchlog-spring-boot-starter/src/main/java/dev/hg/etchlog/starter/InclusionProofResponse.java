package dev.hg.etchlog.starter;

import java.util.List;

/**
 * An inclusion proof returned by the log server for a given leaf.
 *
 * <p>Pass this to a verifier (e.g., the {@code etchlog-cli} or the in-browser verifier) along with
 * the leaf data and the root hash from a trusted STH to prove the record exists in the log at
 * {@code leafIndex}.
 *
 * @param leafIndex zero-based index of the leaf in the log
 * @param treeSize the log size at which the proof was computed
 * @param auditPath the sibling hashes that reconstruct the root (RFC 6962 §2.1.1)
 */
public record InclusionProofResponse(long leafIndex, long treeSize, List<byte[]> auditPath) {}
