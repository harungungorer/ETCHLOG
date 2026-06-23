package dev.hg.etchlog.starter;

import dev.hg.etchlog.core.sth.SignedTreeHead;

/**
 * The result of a successful append operation.
 *
 * <p>The {@code leafIndex} is the permanent, provable position of the appended record in the log.
 * Store it alongside the domain entity to be able to request an inclusion proof later.
 *
 * @param leafIndex zero-based index assigned to the newly appended leaf
 * @param sth the Signed Tree Head committing to the log state after this append
 */
public record AppendResult(long leafIndex, SignedTreeHead sth) {}
