package dev.hg.etchlog.cli.io;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Jackson views of the exact JSON the Etchlog REST API emits, so a verifier can read a proof or STH
 * straight from a saved {@code curl} response.
 *
 * <p>These records mirror the server's public contract — {@code byte[]} fields are standard Base64
 * (Jackson's default {@code byte[]} encoding, matching the server), field names are snake_case.
 * Parsing JSON is <em>not</em> trust: every value is re-checked cryptographically against the log's
 * Ed25519 public key by {@code etchlog-core}. A tampered proof file simply fails verification.
 */
public final class ProofJson {

    /**
     * Shared mapper. {@code FAIL_ON_UNKNOWN_PROPERTIES} is off so extra server fields (e.g. an
     * entry payload echoed alongside a proof) never break parsing.
     */
    private static final ObjectMapper MAPPER =
            new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private ProofJson() {}

    /** A Signed Tree Head: {@code { tree_size, root_hash, timestamp, ed25519_signature }}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Sth(
            @JsonProperty("tree_size") long treeSize,
            @JsonProperty("root_hash") byte[] rootHash,
            @JsonProperty("timestamp") long timestamp,
            @JsonProperty("ed25519_signature") byte[] signature) {}

    /** An inclusion proof: {@code { leaf_index, tree_size, audit_path }}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Inclusion(
            @JsonProperty("leaf_index") long leafIndex,
            @JsonProperty("tree_size") long treeSize,
            @JsonProperty("audit_path") List<byte[]> auditPath) {}

    /** A consistency proof: {@code { first, second, proof }}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Consistency(
            @JsonProperty("first") long first,
            @JsonProperty("second") long second,
            @JsonProperty("proof") List<byte[]> proof) {}

    public static Sth readSth(Path file) throws IOException {
        return read(file, Sth.class);
    }

    public static Inclusion readInclusion(Path file) throws IOException {
        return read(file, Inclusion.class);
    }

    public static Consistency readConsistency(Path file) throws IOException {
        return read(file, Consistency.class);
    }

    /** Reads {@code -} as stdin, any other path as a file. */
    private static <T> T read(Path file, Class<T> type) throws IOException {
        if (file.toString().equals("-")) {
            try (InputStream in = System.in) {
                return MAPPER.readValue(in, type);
            }
        }
        try (InputStream in = Files.newInputStream(file)) {
            return MAPPER.readValue(in, type);
        }
    }
}
