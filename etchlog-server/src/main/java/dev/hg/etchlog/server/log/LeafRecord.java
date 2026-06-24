package dev.hg.etchlog.server.log;

/**
 * Immutable value view of a stored leaf, returned by {@link LogService} so callers never handle a
 * JPA entity directly. This keeps the persistence boundary one-way: the web layer maps a {@code
 * LeafRecord} into its transport DTO without importing {@code persistence.entity.LeafEntity}.
 *
 * <p>The {@code byte[]} fields are defensively copied on the way in and on the way out, so a {@code
 * LeafRecord} is a self-contained snapshot detached from the entity it was projected from.
 *
 * @param leafIndex the zero-based position of this leaf in the log
 * @param payload the original record bytes, or {@code null} when only a precomputed leaf hash was
 *     submitted
 * @param leafHash the RFC 6962 leaf hash ({@code SHA-256(0x00 || payload)}), exactly 32 bytes
 */
public record LeafRecord(long leafIndex, byte[] payload, byte[] leafHash) {

    public LeafRecord {
        payload = payload == null ? null : payload.clone();
        leafHash = leafHash == null ? null : leafHash.clone();
    }

    @Override
    public byte[] payload() {
        return payload == null ? null : payload.clone();
    }

    @Override
    public byte[] leafHash() {
        return leafHash == null ? null : leafHash.clone();
    }
}
