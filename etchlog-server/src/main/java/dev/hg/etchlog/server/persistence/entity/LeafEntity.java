package dev.hg.etchlog.server.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Arrays;

/**
 * An appended record at a fixed {@code leaf_index} (= append order). The append-only record store.
 *
 * <p>One row per appended entry. The {@code leaf_index} is assigned by the single-writer sequencer
 * (it equals the tree size at insert time) and is never reused or reordered. There are no setters:
 * a leaf is immutable once constructed, mirroring the storage-layer append-only invariant.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
@Entity
@Table(name = "leaves")
public class LeafEntity {

    @Id
    @Column(name = "leaf_index", nullable = false, updatable = false)
    private Long leafIndex;

    /**
     * RFC 6962 leaf hash: {@code SHA-256(0x00 || payload)}, exactly 32 bytes. The fixed length is
     * enforced by the constructor and a DB CHECK constraint — {@code @Column(length=…)} is a no-op
     * for binary (BYTEA/BLOB) columns, so it is deliberately omitted here.
     */
    @Column(name = "leaf_hash", nullable = false, updatable = false)
    private byte[] leafHash;

    /** The raw record, or {@code null} when only a precomputed leaf hash was submitted. */
    @Column(name = "payload", updatable = false)
    private byte[] payload;

    @Column(name = "payload_size", nullable = false, updatable = false)
    private int payloadSize;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /** JPA-only. */
    protected LeafEntity() {}

    public LeafEntity(long leafIndex, byte[] leafHash, byte[] payload) {
        if (leafIndex < 0) {
            throw new IllegalArgumentException("leafIndex must be >= 0");
        }
        if (leafHash == null || leafHash.length != 32) {
            throw new IllegalArgumentException("leafHash must be exactly 32 bytes");
        }
        this.leafIndex = leafIndex;
        this.leafHash = leafHash.clone();
        this.payload = payload == null ? null : payload.clone();
        this.payloadSize = payload == null ? 0 : payload.length;
        this.createdAt = Instant.now();
    }

    public long getLeafIndex() {
        return leafIndex;
    }

    public byte[] getLeafHash() {
        return leafHash.clone();
    }

    public byte[] getPayload() {
        return payload == null ? null : payload.clone();
    }

    public int getPayloadSize() {
        return payloadSize;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof LeafEntity other)) {
            return false;
        }
        return leafIndex != null && leafIndex.equals(other.leafIndex);
    }

    @Override
    public int hashCode() {
        return leafIndex == null ? 0 : leafIndex.hashCode();
    }

    @Override
    public String toString() {
        return "LeafEntity{leafIndex="
                + leafIndex
                + ", leafHash="
                + (leafHash == null ? "null" : Arrays.toString(Arrays.copyOf(leafHash, 4)) + "...")
                + ", payloadSize="
                + payloadSize
                + '}';
    }
}
