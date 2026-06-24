package dev.hg.etchlog.server.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Hashes an API key for storage and comparison. The server holds only the hash, so a leaked config
 * dump or heap snapshot never reveals a usable credential.
 *
 * <p>API keys are high-entropy random tokens (≥ 256 bits of CSPRNG output), so a single fast
 * SHA-256 is appropriate here — unlike user passwords, which are low-entropy and human-chosen and
 * therefore need a slow KDF (bcrypt/argon2). A brute-force search over the full key space of a
 * 256-bit token is infeasible regardless of hash speed.
 *
 * @see <a
 *     href="../../../../../../../../docs/features/APPENDER_AUTHORIZATION.md">APPENDER_AUTHORIZATION.md</a>
 */
public final class ApiKeyHasher {

    private ApiKeyHasher() {}

    /**
     * Returns the raw 32-byte SHA-256 of the raw key. This is the on-disk form stored in {@code
     * api_keys.key_hash} (a 32-byte {@code BYTEA}/{@code BLOB}); the hex rendering below is the
     * in-memory comparison form.
     */
    public static byte[] sha256Bytes(String rawKey) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(rawKey.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on the JDK", e);
        }
    }

    /**
     * Returns the lowercase hex SHA-256 of the raw key. {@link HexFormat} is locale-independent by
     * construction, satisfying the project's {@code Locale.ROOT} hygiene rule.
     */
    public static String sha256Hex(String rawKey) {
        return HexFormat.of().formatHex(sha256Bytes(rawKey));
    }
}
