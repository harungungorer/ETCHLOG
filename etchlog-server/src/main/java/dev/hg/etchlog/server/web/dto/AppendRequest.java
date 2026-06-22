package dev.hg.etchlog.server.web.dto;

import jakarta.validation.constraints.NotEmpty;

/**
 * Append request body for {@code POST /api/v1/log/entries}.
 *
 * <p>{@code leaf_data} is the raw record payload, standard-Base64 encoded; Jackson decodes it to
 * the exact bytes the appender submitted, which are then stored verbatim and RFC 6962 leaf-hashed.
 * The hash is never recomputed from a re-parsed form, so encoding round-trips can never change a
 * proof.
 *
 * @param leafData decoded payload bytes (must be present and non-empty)
 */
public record AppendRequest(
        @NotEmpty(message = "leaf_data must be present and non-empty") byte[] leafData) {}
