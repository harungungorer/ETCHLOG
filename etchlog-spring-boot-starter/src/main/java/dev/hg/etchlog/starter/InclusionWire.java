package dev.hg.etchlog.starter;

import java.util.List;

/**
 * Internal wire DTO for deserializing the inclusion proof response from the server.
 *
 * <p>Maps the server JSON:
 *
 * <pre>{@code
 * {"leaf_index": 0, "tree_size": 1, "audit_path": ["<b64>", ...]}
 * }</pre>
 */
record InclusionWire(long leafIndex, long treeSize, List<byte[]> auditPath) {

    /** Convert to the public {@link InclusionProofResponse}. */
    InclusionProofResponse toInclusionProofResponse() {
        return new InclusionProofResponse(leafIndex, treeSize, auditPath);
    }
}
