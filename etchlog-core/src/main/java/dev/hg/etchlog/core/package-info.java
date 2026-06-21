/**
 * Etchlog cryptographic core — pure Java 21, <strong>zero framework dependencies</strong>.
 *
 * <p>This module is the single source of truth for RFC 6962 Merkle-tree math, inclusion and
 * consistency proofs, and Ed25519 Signed Tree Head signing/verification. The exact same code runs
 * server-side, in the CLI verifier, and as the reference the TypeScript browser verifier is checked
 * against. It must never import {@code org.springframework.*}, JPA, or web types — a boundary
 * enforced by the {@code CryptoCorePurityTest} ArchUnit rule.
 *
 * <p>Public API surface consumed by {@code etchlog-server}, {@code etchlog-cli}, and {@code
 * etchlog-spring-boot-starter}:
 *
 * <ul>
 *   <li>{@link dev.hg.etchlog.core.hash.MerkleHash} — RFC 6962 leaf/node hashing.
 *   <li>{@link dev.hg.etchlog.core.tree.MerkleTreeHash} / {@link
 *       dev.hg.etchlog.core.tree.CachedMerkleTree} — tree-head (root) computation.
 *   <li>{@link dev.hg.etchlog.core.proof.InclusionProof} / {@link
 *       dev.hg.etchlog.core.proof.InclusionVerifier} — inclusion-proof generation and standalone
 *       verification.
 *   <li>{@link dev.hg.etchlog.core.proof.ConsistencyProof} / {@link
 *       dev.hg.etchlog.core.proof.ConsistencyVerifier} — consistency-proof generation and
 *       standalone verification.
 *   <li>{@link dev.hg.etchlog.core.sth.SignedTreeHead}, {@link
 *       dev.hg.etchlog.core.sth.SthEncoding}, {@link dev.hg.etchlog.core.sth.Ed25519SthSigner},
 *       {@link dev.hg.etchlog.core.sth.SthVerifier} — the STH model, canonical serialization, and
 *       Ed25519 signing/verification.
 * </ul>
 */
package dev.hg.etchlog.core;
