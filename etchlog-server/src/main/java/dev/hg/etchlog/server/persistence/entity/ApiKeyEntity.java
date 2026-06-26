package dev.hg.etchlog.server.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * An appender credential. Reads/proofs are public, so only the write path consults this table.
 *
 * <p>Keys are stored <strong>hashed</strong> ({@code SHA-256} of the key), never in plaintext, and
 * are validated by hash lookup. The UUID id is generated in the application layer so the same code
 * path works for both PostgreSQL and SQLite (SQLite has no {@code gen_random_uuid()}). Rotation and
 * revocation toggle {@code active}/{@code revoked_at}; unlike the log tables this row is mutable,
 * as it carries no cryptographic commitment.
 *
 * @see <a
 *     href="../../../../../../../../docs/architecture/DATABASE_SCHEMA.md">DATABASE_SCHEMA.md</a>
 */
@Entity
@Table(name = "api_keys")
public class ApiKeyEntity {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    /**
     * {@code SHA-256} hash of the API key; never the plaintext. Exactly 32 bytes, enforced by the
     * constructor and a DB CHECK constraint; {@code @Column(length=…)} is a no-op for binary
     * columns, so it is omitted (unlike {@code label} below, a VARCHAR where length applies).
     */
    @Column(name = "key_hash", nullable = false, updatable = false)
    private byte[] keyHash;

    /** Operator-assigned, set once at issuance; {@code updatable = false} keeps it immutable. */
    @Column(name = "label", nullable = false, updatable = false, length = 128)
    private String label;

    @Column(name = "active", nullable = false)
    private boolean active;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    /** JPA-only. */
    protected ApiKeyEntity() {}

    public ApiKeyEntity(byte[] keyHash, String label) {
        if (keyHash == null || keyHash.length != 32) {
            throw new IllegalArgumentException("keyHash must be exactly 32 bytes");
        }
        if (label == null || label.isBlank()) {
            throw new IllegalArgumentException("label must not be blank");
        }
        this.id = UUID.randomUUID();
        this.keyHash = keyHash.clone();
        this.label = label;
        this.active = true;
        this.createdAt = Instant.now();
    }

    /** Revoke this key: deactivate it and stamp the revocation time. Idempotent. */
    public void revoke() {
        if (this.active) {
            this.active = false;
            this.revokedAt = Instant.now();
        }
    }

    public UUID getId() {
        return id;
    }

    public byte[] getKeyHash() {
        return keyHash.clone();
    }

    public String getLabel() {
        return label;
    }

    public boolean isActive() {
        return active;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ApiKeyEntity other)) {
            return false;
        }
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return id == null ? 0 : id.hashCode();
    }

    @Override
    public String toString() {
        return "ApiKeyEntity{id=" + id + ", label='" + label + "', active=" + active + '}';
    }
}
