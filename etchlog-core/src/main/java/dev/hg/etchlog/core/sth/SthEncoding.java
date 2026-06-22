package dev.hg.etchlog.core.sth;

import dev.hg.etchlog.core.hash.MerkleHash;
import java.nio.ByteBuffer;

/**
 * Deterministic, version-tagged byte layout that Ed25519 signs and verifies.
 *
 * <pre>
 *   to_be_signed =  0x00                 (STH version/structure byte)
 *                || uint64_be(tree_size) (8 bytes, big-endian)
 *                || uint64_be(timestamp) (8 bytes, big-endian)
 *                || root_hash            (32 bytes)
 * </pre>
 *
 * <p>The signature covers this fixed, unambiguous layout — never the JSON rendering, whose
 * whitespace and key ordering are not canonical and would make signatures non-reproducible across
 * languages (including the TypeScript browser verifier).
 *
 * <p><strong>Not the RFC 6962 §3.5 {@code TreeHeadSignature} wire format.</strong> This is
 * Etchlog's own canonical STH encoding, deliberately distinct from Certificate Transparency's
 * on-the-wire layout: CT prepends a {@code signature_type} byte and orders the fields {@code
 * timestamp} then {@code tree_size}, whereas Etchlog uses a single structure/version tag and orders
 * {@code tree_size} then {@code timestamp}. Full CT submission/wire compatibility is an explicit
 * non-goal (see {@code docs/reference/ROADMAP.md} and {@code docs/operations/MAINTENANCE.md});
 * Etchlog implements the RFC 6962 Merkle algorithms, not the CT serialization. The encoding is
 * self-consistent (the signer and every Etchlog verifier — server, CLI, browser — use exactly these
 * bytes) and fully fixed-width, so it carries no canonicalization ambiguity. Do not assume STHs
 * verify under stock CT tooling.
 */
public final class SthEncoding {

    /** Structure/version tag prefixed to every signed STH payload. */
    public static final byte STH_VERSION = 0x00;

    /** Fixed signed-payload width: 1 version + 8 tree_size + 8 timestamp + 32 root. */
    public static final int SIGNED_LENGTH = 1 + 8 + 8 + MerkleHash.HASH_LENGTH;

    private SthEncoding() {}

    /** Produces the exact bytes an Ed25519 signature covers for the given STH fields. */
    public static byte[] bytesToSign(long treeSize, long timestampMs, byte[] rootHash) {
        if (rootHash == null || rootHash.length != MerkleHash.HASH_LENGTH) {
            throw new IllegalArgumentException("root must be " + MerkleHash.HASH_LENGTH + " bytes");
        }
        return ByteBuffer.allocate(SIGNED_LENGTH)
                .put(STH_VERSION) // structure/version tag
                .putLong(treeSize) // big-endian by default
                .putLong(timestampMs)
                .put(rootHash)
                .array();
    }
}
