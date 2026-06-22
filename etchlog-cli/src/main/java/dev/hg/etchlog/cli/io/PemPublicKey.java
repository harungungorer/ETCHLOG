package dev.hg.etchlog.cli.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Locale;

/**
 * Loads the log's Ed25519 <em>public</em> key from an X.509/SPKI PEM file (a {@code PUBLIC KEY}
 * armored block) — the only key material a verifier ever needs. Mirrors the server's PEM decoding
 * so a key file written by the operator loads identically here.
 */
public final class PemPublicKey {

    private static final String LABEL = "PUBLIC KEY";

    private PemPublicKey() {}

    /**
     * @throws IllegalArgumentException if the file is missing, not a {@code PUBLIC KEY} PEM block,
     *     or not a valid Ed25519 SPKI key
     */
    public static PublicKey load(Path pem) {
        byte[] der = decodePem(pem);
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(
                    "Not a valid Ed25519 public key: " + pem + " (" + e.getMessage() + ")", e);
        }
    }

    /** Returns the DER bytes between the BEGIN/END armor lines of a {@code PUBLIC KEY} block. */
    private static byte[] decodePem(Path pem) {
        String contents;
        try {
            contents = Files.readString(pem);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read public-key PEM file: " + pem, e);
        }
        String base64 =
                contents.replace("-----BEGIN " + LABEL + "-----", "")
                        .replace("-----END " + LABEL + "-----", "")
                        .replaceAll("\\s", "");
        if (base64.isEmpty()) {
            throw new IllegalArgumentException(
                    "PEM file "
                            + pem
                            + " contains no '"
                            + LABEL
                            + "' block (expected an X.509/SPKI 'PUBLIC KEY' PEM)");
        }
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "PEM file " + pem + " is not valid base64 for a " + LABEL + " block", e);
        }
    }

    /**
     * Decodes a 32-byte hash supplied on the command line. Accepts standard Base64 (what {@code jq
     * -r .root_hash} yields), Base64URL, or 64-char hex — whichever the user pastes.
     *
     * @throws IllegalArgumentException if the value decodes to something other than 32 bytes
     */
    public static byte[] decodeHash(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("hash value must not be empty");
        }
        String v = value.trim();
        byte[] bytes = tryDecode(v);
        if (bytes == null) {
            throw new IllegalArgumentException(
                    "hash is not valid base64, base64url, or hex: " + value);
        }
        if (bytes.length != 32) {
            throw new IllegalArgumentException(
                    "hash must decode to 32 bytes (SHA-256), got " + bytes.length);
        }
        return bytes;
    }

    private static byte[] tryDecode(String v) {
        if (v.length() == 64 && v.chars().allMatch(PemPublicKey::isHexDigit)) {
            return hexToBytes(v);
        }
        try {
            return Base64.getDecoder().decode(v);
        } catch (IllegalArgumentException ignored) {
            // not standard base64 — try url-safe
        }
        try {
            return Base64.getUrlDecoder().decode(v);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static boolean isHexDigit(int c) {
        char ch = Character.toLowerCase((char) c);
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    }

    private static byte[] hexToBytes(String hex) {
        String h = hex.toLowerCase(Locale.ROOT);
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
