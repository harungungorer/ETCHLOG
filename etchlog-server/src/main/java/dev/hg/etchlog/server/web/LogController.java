package dev.hg.etchlog.server.web;

import dev.hg.etchlog.server.config.OpenApiConfig;
import dev.hg.etchlog.server.log.AppendResult;
import dev.hg.etchlog.server.log.LogService;
import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import dev.hg.etchlog.server.web.dto.AppendRequest;
import dev.hg.etchlog.server.web.dto.AppendResponse;
import dev.hg.etchlog.server.web.dto.ConsistencyProofResponse;
import dev.hg.etchlog.server.web.dto.EntryResponse;
import dev.hg.etchlog.server.web.dto.InclusionProofResponse;
import dev.hg.etchlog.server.web.dto.SthResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.Base64;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST surface of the transparency log under {@code /api/v1/log}.
 *
 * <p>Controllers here stay thin: they validate and shape requests/responses, delegating all
 * sequencing and cryptography to {@link LogService} and {@code etchlog-core}. Appends are
 * authenticated (see the security configuration); reads and proofs are public.
 *
 * @see <a href="../../../../../../../../docs/api/API_DOCUMENTATION.md">API_DOCUMENTATION.md</a>
 */
@RestController
@RequestMapping("/api/v1/log")
@Tag(
        name = "Transparency log",
        description =
                "Append records and verify inclusion/consistency proofs against the signed tree"
                        + " head. Reads and proofs are public; appends are authenticated.")
public class LogController {

    private static final String PROBLEM_JSON = "application/problem+json";

    /** Length of an RFC 6962 leaf hash (SHA-256), in bytes. */
    private static final int LEAF_HASH_LENGTH = 32;

    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    /**
     * Appends one record. The leaf is RFC 6962 leaf-hashed, sequenced, and a fresh STH is signed.
     *
     * @return {@code 201 Created} with the assigned {@code leaf_index} and the resulting STH
     */
    @Operation(
            summary = "Append a record",
            description =
                    "Leaf-hashes the submitted record (SHA-256(0x00 || leaf_data)), assigns the next"
                            + " leaf index, and returns a freshly signed tree head committing to it.")
    @ApiResponse(responseCode = "201", description = "Appended; returns leaf_index and the new STH")
    @ApiResponse(
            responseCode = "400",
            description = "Missing or empty leaf_data",
            content = @Content(mediaType = PROBLEM_JSON))
    @ApiResponse(
            responseCode = "401",
            description = "Missing or invalid X-Api-Key",
            content = @Content(mediaType = PROBLEM_JSON))
    @ApiResponse(
            responseCode = "409",
            description = "A record with this leaf hash is already in the log",
            content = @Content(mediaType = PROBLEM_JSON))
    @SecurityRequirement(name = OpenApiConfig.API_KEY_SCHEME)
    @PostMapping(
            path = "/entries",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public AppendResponse append(@Valid @RequestBody AppendRequest request) {
        AppendResult result = logService.append(request.leafData());
        return AppendResponse.from(result);
    }

    /**
     * Fetches the stored leaf at the given zero-based index. Public — no authentication required.
     *
     * @param index the leaf index ({@code 0 ≤ index < tree_size})
     * @return {@code 200 OK} with {@code leaf_index}, {@code leaf_data} (standard Base64), and
     *     {@code leaf_hash} (standard Base64)
     * @throws IllegalArgumentException mapped to {@code 400} when {@code index} is negative
     * @throws LeafNotFoundException mapped to {@code 404} when no leaf exists at that index
     */
    @Operation(
            summary = "Get entry by index",
            description =
                    "Fetches the stored leaf at a zero-based index. Public — no auth required.")
    @ApiResponse(responseCode = "200", description = "The leaf at the given index")
    @ApiResponse(
            responseCode = "400",
            description = "Negative leaf index",
            content = @Content(mediaType = PROBLEM_JSON))
    @ApiResponse(
            responseCode = "404",
            description = "No leaf exists at that index",
            content = @Content(mediaType = PROBLEM_JSON))
    @GetMapping(path = "/entries/{index}", produces = MediaType.APPLICATION_JSON_VALUE)
    public EntryResponse getEntryByIndex(
            @Parameter(description = "Zero-based leaf index (0 ≤ index < tree_size)")
                    @PathVariable("index")
                    long index) {
        if (index < 0) {
            throw new IllegalArgumentException("leaf index must be non-negative; got " + index);
        }
        LeafEntity leaf =
                logService
                        .findEntry(index)
                        .orElseThrow(
                                () ->
                                        new LeafNotFoundException(
                                                "No leaf exists at index " + index));
        return EntryResponse.from(leaf);
    }

    /**
     * Looks up a leaf by its RFC 6962 leaf hash supplied as a Base64URL query parameter. Public —
     * no authentication required.
     *
     * <p>The {@code hash} query parameter must be Base64URL-encoded (RFC 4648 §5, {@code -}/{@code
     * _}, no padding). Standard Base64 ({@code +}/{@code /}) without percent-encoding will be
     * misparsed and may yield a {@code 400} or {@code 404}.
     *
     * @param hash the leaf hash in Base64URL encoding (no padding)
     * @return {@code 200 OK} with the same shape as {@link #getEntryByIndex}
     * @throws LeafNotFoundException mapped to {@code 404} when no leaf with that hash is found
     * @throws IllegalArgumentException mapped to {@code 400} by {@link ApiExceptionHandler} when
     *     {@code hash} is not valid Base64URL or does not decode to a 32-byte hash
     */
    @Operation(
            summary = "Get entry by hash",
            description =
                    "Looks up a leaf by its RFC 6962 leaf hash, supplied as Base64URL (no padding)."
                            + " Public — no auth required.")
    @ApiResponse(responseCode = "200", description = "The leaf with the given hash")
    @ApiResponse(
            responseCode = "400",
            description = "hash is not valid Base64URL or does not decode to 32 bytes",
            content = @Content(mediaType = PROBLEM_JSON))
    @ApiResponse(
            responseCode = "404",
            description = "No leaf with that hash exists",
            content = @Content(mediaType = PROBLEM_JSON))
    @GetMapping(path = "/entries", produces = MediaType.APPLICATION_JSON_VALUE)
    public EntryResponse getEntryByHash(
            @Parameter(description = "Leaf hash, Base64URL-encoded (RFC 4648 §5, no padding)")
                    @RequestParam("hash")
                    String hash) {
        byte[] leafHash;
        try {
            leafHash = Base64.getUrlDecoder().decode(hash);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(
                    "hash must be valid Base64URL (RFC 4648 §5, no padding): " + ex.getMessage());
        }
        if (leafHash.length != LEAF_HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "hash must decode to "
                            + LEAF_HASH_LENGTH
                            + " bytes (a SHA-256 leaf hash); got "
                            + leafHash.length);
        }
        LeafEntity leaf =
                logService
                        .findEntryByHash(leafHash)
                        .orElseThrow(
                                () ->
                                        new LeafNotFoundException(
                                                "No leaf with the given hash exists in the log"));
        return EntryResponse.from(leaf);
    }

    /**
     * Generates an inclusion (audit) proof that the leaf at {@code leaf_index} is committed in the
     * tree of size {@code tree_size}. Public — no authentication required.
     *
     * @return {@code 200 OK} with {@code leaf_index}, {@code tree_size}, and the {@code audit_path}
     * @throws IllegalArgumentException mapped to {@code 400} for an out-of-range index/size
     * @throws dev.hg.etchlog.server.log.ProofNotAvailableException mapped to {@code 404} when
     *     {@code tree_size} exceeds the current log size
     */
    @Operation(
            summary = "Inclusion proof",
            description =
                    "Returns the RFC 6962 audit path proving the leaf at leaf_index is committed in"
                            + " the tree of size tree_size. Public — no auth required.")
    @ApiResponse(responseCode = "200", description = "leaf_index, tree_size, and the audit_path")
    @ApiResponse(
            responseCode = "400",
            description = "Out-of-range leaf_index or tree_size",
            content = @Content(mediaType = PROBLEM_JSON))
    @ApiResponse(
            responseCode = "404",
            description = "tree_size exceeds the current log size",
            content = @Content(mediaType = PROBLEM_JSON))
    @GetMapping(path = "/proofs/inclusion", produces = MediaType.APPLICATION_JSON_VALUE)
    public InclusionProofResponse inclusionProof(
            @Parameter(description = "Zero-based index of the leaf to prove")
                    @RequestParam("leaf_index")
                    long leafIndex,
            @Parameter(description = "Tree size (STH) the proof is relative to")
                    @RequestParam("tree_size")
                    long treeSize) {
        return new InclusionProofResponse(
                leafIndex, treeSize, logService.inclusionAuditPath(leafIndex, treeSize));
    }

    /**
     * Generates a consistency proof that the size-{@code first} log is an append-only prefix of the
     * size-{@code second} log. Public — no authentication required.
     *
     * @return {@code 200 OK} with {@code first}, {@code second}, and the {@code proof} nodes
     * @throws IllegalArgumentException mapped to {@code 400} when {@code first > second} or
     *     negative
     * @throws dev.hg.etchlog.server.log.ProofNotAvailableException mapped to {@code 404} when
     *     {@code second} exceeds the current log size
     */
    @Operation(
            summary = "Consistency proof",
            description =
                    "Returns the RFC 6962 consistency proof that the size-first log is an"
                            + " append-only prefix of the size-second log. Public — no auth"
                            + " required.")
    @ApiResponse(responseCode = "200", description = "first, second, and the proof nodes")
    @ApiResponse(
            responseCode = "400",
            description = "first > second, or a negative size",
            content = @Content(mediaType = PROBLEM_JSON))
    @ApiResponse(
            responseCode = "404",
            description = "second exceeds the current log size",
            content = @Content(mediaType = PROBLEM_JSON))
    @GetMapping(path = "/proofs/consistency", produces = MediaType.APPLICATION_JSON_VALUE)
    public ConsistencyProofResponse consistencyProof(
            @Parameter(description = "Earlier tree size (the prefix)") @RequestParam("first")
                    long first,
            @Parameter(description = "Later tree size (the superset)") @RequestParam("second")
                    long second) {
        return new ConsistencyProofResponse(
                first, second, logService.consistencyProofNodes(first, second));
    }

    /**
     * Returns the log's latest Signed Tree Head (the genesis empty STH for an empty log). Public —
     * no authentication required.
     */
    @Operation(
            summary = "Current signed tree head",
            description =
                    "Returns the log's latest Ed25519-signed tree head (the genesis empty STH for an"
                            + " empty log). Public — no auth required.")
    @ApiResponse(responseCode = "200", description = "The current STH")
    @GetMapping(path = "/sth", produces = MediaType.APPLICATION_JSON_VALUE)
    public SthResponse signedTreeHead() {
        return SthResponse.from(logService.currentSth());
    }
}
