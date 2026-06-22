package dev.hg.etchlog.server.web.dto;

import dev.hg.etchlog.server.log.AppendResult;

/**
 * Success body for {@code POST /api/v1/log/entries}: the index assigned to the new leaf and the STH
 * committing to the log including it ({@code sth.tree_size == leaf_index + 1}).
 *
 * @param leafIndex index assigned to the newly appended leaf
 * @param sth the resulting Signed Tree Head
 */
public record AppendResponse(long leafIndex, SthResponse sth) {

    public static AppendResponse from(AppendResult result) {
        return new AppendResponse(result.leafIndex(), SthResponse.from(result.sth()));
    }
}
