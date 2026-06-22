package dev.hg.etchlog.server.web.dto;

import dev.hg.etchlog.server.persistence.entity.LeafEntity;

/**
 * JSON view of a single leaf entry, matching the public contract {@code { leaf_index, leaf_data,
 * leaf_hash }}.
 *
 * <p>The {@code byte[]} fields ({@code leafData}, {@code leafHash}) serialize as standard Base64
 * (Jackson's default {@code byte[]} encoding) and the field names render in snake_case via the
 * application-wide naming strategy. {@code leafData} may be {@code null} when only a pre-computed
 * leaf hash was originally submitted — callers must tolerate a {@code null} / absent {@code
 * leaf_data} field.
 *
 * @param leafIndex the zero-based position of this leaf in the log
 * @param leafData the original record payload, or {@code null} if not stored
 * @param leafHash the RFC 6962 leaf hash ({@code SHA-256(0x00 || payload)}), exactly 32 bytes
 * @see <a href="../../../../../../../../docs/api/API_DOCUMENTATION.md">API_DOCUMENTATION.md
 *     §2–3</a>
 */
public record EntryResponse(long leafIndex, byte[] leafData, byte[] leafHash) {

    /** Projects a {@link LeafEntity} into its public JSON shape. */
    public static EntryResponse from(LeafEntity leaf) {
        return new EntryResponse(leaf.getLeafIndex(), leaf.getPayload(), leaf.getLeafHash());
    }
}
