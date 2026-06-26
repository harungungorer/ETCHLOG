package dev.hg.etchlog.server.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One row of the immutable STH history, keyed by {@code tree_size}.
 *
 * <p>Each append inserts a new STH row (never updates an old one), so the log can serve a
 * consistency proof between any two historical sizes a monitor previously observed. Maps directly
 * to the public STH JSON shape {@code { tree_size, root_hash, timestamp, ed25519_signature }}. The
 * Ed25519 signature is produced in {@code etchlog-core} over the canonical STH serialization; the
 * DB stores only the signature, never the key.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
@Entity
@Table(name = "signed_tree_heads")
public class SignedTreeHeadEntity {

    /** Number of leaves committed by this STH. */
    @Id
    @Column(name = "tree_size", nullable = false, updatable = false)
    private Long treeSize;

    // Exactly 32 bytes (constructor + DB CHECK). length=… is a no-op on binary columns; omitted.
    @Column(name = "root_hash", nullable = false, updatable = false)
    private byte[] rootHash;

    /** Cryptographic STH timestamp (signed) — distinct from the operational {@code created_at}. */
    @Column(name = "timestamp", nullable = false, updatable = false)
    private Instant timestamp;

    // Exactly 64 bytes (constructor + DB CHECK). length=… is a no-op on binary columns; omitted.
    @Column(name = "ed25519_signature", nullable = false, updatable = false)
    private byte[] ed25519Signature;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /** JPA-only. */
    protected SignedTreeHeadEntity() {}

    public SignedTreeHeadEntity(
            long treeSize, byte[] rootHash, Instant timestamp, byte[] ed25519Signature) {
        if (treeSize < 0) {
            throw new IllegalArgumentException("treeSize must be >= 0");
        }
        if (rootHash == null || rootHash.length != 32) {
            throw new IllegalArgumentException("rootHash must be exactly 32 bytes");
        }
        if (timestamp == null) {
            throw new IllegalArgumentException("timestamp must not be null");
        }
        if (ed25519Signature == null || ed25519Signature.length != 64) {
            throw new IllegalArgumentException("ed25519Signature must be exactly 64 bytes");
        }
        this.treeSize = treeSize;
        this.rootHash = rootHash.clone();
        this.timestamp = timestamp;
        this.ed25519Signature = ed25519Signature.clone();
        this.createdAt = Instant.now();
    }

    public long getTreeSize() {
        return treeSize;
    }

    public byte[] getRootHash() {
        return rootHash.clone();
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public byte[] getEd25519Signature() {
        return ed25519Signature.clone();
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SignedTreeHeadEntity other)) {
            return false;
        }
        return treeSize != null && treeSize.equals(other.treeSize);
    }

    @Override
    public int hashCode() {
        return treeSize == null ? 0 : treeSize.hashCode();
    }

    @Override
    public String toString() {
        return "SignedTreeHeadEntity{treeSize=" + treeSize + ", timestamp=" + timestamp + '}';
    }
}
