package dev.hg.etchlog.server.web;

import dev.hg.etchlog.server.log.AppendResult;
import dev.hg.etchlog.server.log.LogService;
import dev.hg.etchlog.server.web.dto.AppendRequest;
import dev.hg.etchlog.server.web.dto.AppendResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
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
}
