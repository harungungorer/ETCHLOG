package dev.hg.etchlog.server.log;

import dev.hg.etchlog.core.sth.SignedTreeHead;

/**
 * The outcome of a single append: the index assigned to the new leaf and the Signed Tree Head that
 * commits to the log including it.
 *
 * <p>Maps directly to the {@code POST /api/v1/log/entries} success body {@code { leaf_index, sth
 * }}; note {@code sth.treeSize() == leafIndex + 1}.
 *
 * @param leafIndex 0-based index assigned by the single sequencer
 * @param sth the signed head over leaves {@code 0..leafIndex}
 */
public record AppendResult(long leafIndex, SignedTreeHead sth) {}
