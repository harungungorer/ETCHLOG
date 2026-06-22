package dev.hg.etchlog.server.web;

import dev.hg.etchlog.server.log.AppendResult;
import dev.hg.etchlog.server.log.LogService;
import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import dev.hg.etchlog.server.web.dto.AppendRequest;
import dev.hg.etchlog.server.web.dto.AppendResponse;
import dev.hg.etchlog.server.web.dto.ConsistencyProofResponse;
import dev.hg.etchlog.server.web.dto.EntryResponse;
import dev.hg.etchlog.server.web.dto.InclusionProofResponse;
import dev.hg.etchlog.server.web.dto.SthResponse;
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
public class LogController {

    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    /**
     * Appends one record. The leaf is RFC 6962 leaf-hashed, sequenced, and a fresh STH is signed.
     *
     * @return {@code 201 Created} with the assigned {@code leaf_index} and the resulting STH
     */
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
     * @throws LeafNotFoundException mapped to {@code 404} when no leaf exists at that index
     */
    @GetMapping(path = "/entries/{index}", produces = MediaType.APPLICATION_JSON_VALUE)
    public EntryResponse getEntryByIndex(@PathVariable("index") long index) {
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
     *     {@code hash} is not valid Base64URL
     */
    @GetMapping(path = "/entries", produces = MediaType.APPLICATION_JSON_VALUE)
    public EntryResponse getEntryByHash(@RequestParam("hash") String hash) {
        byte[] leafHash = Base64.getUrlDecoder().decode(hash);
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
    @GetMapping(path = "/proofs/inclusion", produces = MediaType.APPLICATION_JSON_VALUE)
    public InclusionProofResponse inclusionProof(
            @RequestParam("leaf_index") long leafIndex, @RequestParam("tree_size") long treeSize) {
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
    @GetMapping(path = "/proofs/consistency", produces = MediaType.APPLICATION_JSON_VALUE)
    public ConsistencyProofResponse consistencyProof(
            @RequestParam("first") long first, @RequestParam("second") long second) {
        return new ConsistencyProofResponse(
                first, second, logService.consistencyProofNodes(first, second));
    }

    /**
     * Returns the log's latest Signed Tree Head (the genesis empty STH for an empty log). Public —
     * no authentication required.
     */
    @GetMapping(path = "/sth", produces = MediaType.APPLICATION_JSON_VALUE)
    public SthResponse signedTreeHead() {
        return SthResponse.from(logService.currentSth());
    }
}
