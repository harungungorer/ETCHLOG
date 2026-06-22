package dev.hg.etchlog.server.web.dto;

import java.util.List;

/**
 * JSON view of an inclusion proof, matching the public contract {@code { leaf_index, tree_size,
 * audit_path }}.
 *
 * <p>{@code audit_path} is the ordered list of sibling node hashes that, combined with the leaf
 * hash, recompute the size-{@code tree_size} root. Each hash serializes as standard Base64. A
 * verifier checks the recomputed root against the {@code root_hash} of the STH at {@code
 * tree_size}.
 *
 * @param leafIndex index {@code i} of the leaf being proven
 * @param treeSize tree size {@code N} the proof is relative to
 * @param auditPath ordered sibling hashes from the leaf up to the root
 */
public record InclusionProofResponse(long leafIndex, long treeSize, List<byte[]> auditPath) {}
