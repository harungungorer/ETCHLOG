package dev.hg.etchlog.server.log;

import java.util.Base64;

/**
 * Thrown when an append targets a leaf hash already present in the log.
 *
 * <p>The {@code leaves} table enforces {@code UNIQUE (leaf_hash)}, so the same record cannot occupy
 * two indices. The append path detects this before inserting and surfaces it as a domain error the
 * web layer maps to {@code 409 Conflict}.
 */
public class DuplicateLeafException extends RuntimeException {

    private final transient byte[] leafHash;

    public DuplicateLeafException(byte[] leafHash) {
        super("leaf already present: " + Base64.getEncoder().encodeToString(leafHash));
        this.leafHash = leafHash.clone();
    }

    public byte[] leafHash() {
        return leafHash.clone();
    }
}
