package dev.hg.etchlog.server.demo;

import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import dev.hg.etchlog.server.persistence.repository.LeafRepository;
import dev.hg.etchlog.server.persistence.repository.TreeNodeRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * DEMO-ONLY: simulates a malicious operator silently rewriting a stored record directly in the
 * database — the exact attack Etchlog is designed to make <em>detectable</em>.
 *
 * <p>This service deliberately bypasses every append-only safeguard the application enforces: the
 * {@code leaves}/{@code tree_nodes} entities are immutable ({@code @Column(updatable=false)}) and
 * {@link LeafRepository} exposes no update path, so the only way to mutate a committed leaf is to
 * go <em>around</em> the ORM with native SQL — precisely what an operator with raw DB access would
 * do.
 *
 * <p>It rewrites the leaf and its whole affected subtree, and leaves the signed tree heads
 * untouched:
 *
 * <ol>
 *   <li>{@code leaves}: the {@code payload} and its RFC 6962 {@code leaf_hash};
 *   <li>{@code tree_nodes} at {@code (level 0, node_index = leafIndex)}: the materialized leaf
 *       hash; and
 *   <li>every materialized perfect-subtree node on the path from that leaf up to its highest
 *       complete ancestor, recomputed so the served tree stays internally consistent.
 * </ol>
 *
 * <p>That third step matters because proof generation reads the materialized {@code tree_nodes}
 * directly (an O(log N) path) rather than re-hashing every leaf, so a believable tamper must
 * rewrite the affected subtree — not just the one leaf. The operator still cannot re-sign the STH:
 * because the {@code signed_tree_heads} rows are NOT re-signed, the published head still carries a
 * <em>valid Ed25519 signature</em> over the <em>original</em> root. A verifier therefore sees a
 * perfectly signed head whose committed data no longer matches the store — the (now internally
 * consistent) tampered tree hashes to a different root — so both the inclusion proof (the browser
 * recomputes the leaf hash from the bytes it was handed) and the consistency proof against the
 * original signed roots are rejected. Tamper-evident, exactly as advertised.
 *
 * <p><strong>Never enable the {@code demo} profile in production.</strong> There is no legitimate
 * edit-a-leaf operation in Etchlog.
 */
@Service
@Profile("demo")
public class DemoTamperService {

    /** Visible marker appended to the record so the tampering is obvious in the UI. */
    static final String TAMPER_MARKER = " ⚠ TAMPERED ⚠";

    /** The profile this destructive demo is gated behind; never legitimate in production. */
    static final String DEMO_PROFILE = "demo";

    private final LeafRepository leaves;
    private final TreeNodeRepository nodes;
    private final Environment environment;

    @PersistenceContext private EntityManager em;

    public DemoTamperService(
            LeafRepository leaves, TreeNodeRepository nodes, Environment environment) {
        this.leaves = leaves;
        this.nodes = nodes;
        this.environment = environment;
    }

    /**
     * Mutates the leaf at {@code index} in place. Returns the new (tampered) payload and leaf hash
     * so the caller can show what the operator changed it to.
     *
     * @throws DemoLeafNotFoundException if no leaf exists at {@code index}
     */
    @Transactional
    public TamperResult tamper(long index) {
        assertDemoProfileActive();
        LeafEntity leaf =
                leaves.findById(index)
                        .orElseThrow(
                                () ->
                                        new DemoLeafNotFoundException(
                                                "No leaf exists at index " + index));

        byte[] original = leaf.getPayload();
        String base =
                original != null ? new String(original, StandardCharsets.UTF_8) : "leaf-" + index;
        byte[] tamperedPayload = (base + TAMPER_MARKER).getBytes(StandardCharsets.UTF_8);
        byte[] tamperedHash = MerkleHash.hashLeaf(tamperedPayload);

        int leavesUpdated =
                em.createNativeQuery(
                                "UPDATE leaves SET payload = :p, payload_size = :s, leaf_hash = :h"
                                        + " WHERE leaf_index = :i")
                        .setParameter("p", tamperedPayload)
                        .setParameter("s", tamperedPayload.length)
                        .setParameter("h", tamperedHash)
                        .setParameter("i", index)
                        .executeUpdate();
        if (leavesUpdated != 1) {
            throw new DemoLeafNotFoundException("No leaf exists at index " + index);
        }

        // Rewrite the materialized level-0 node, then recompute every perfect-subtree node on the
        // path from the tampered leaf up to its highest complete ancestor. Proof generation reads
        // these materialized nodes (an O(log N) path, not an O(N) re-hash of every leaf), so a
        // thorough operator must rewrite the whole affected subtree to keep the served tree
        // internally consistent. They cannot, however, re-sign the STH: the signed_tree_heads rows
        // are left untouched, so the now-consistent tampered tree hashes to a root that no longer
        // matches the validly-signed head — and every inclusion/consistency proof checked against
        // that head is rejected. That is the tamper alarm.
        updateNodeHash(0, index, tamperedHash);
        rewriteMaterializedAncestors(index, tamperedHash, leaves.count());

        return new TamperResult(index, tamperedPayload, tamperedHash);
    }

    /**
     * Recomputes and rewrites every materialized perfect-subtree node on the path from the tampered
     * leaf at {@code (level 0, leafIndex)} up to its highest <em>complete</em> ancestor, so the
     * served tree stays internally consistent around the mutation. An ancestor {@code (L, J)} is
     * materialized iff its whole leaf range {@code [J·2^L, (J+1)·2^L)} is populated, i.e. {@code
     * (J+1)·2^L <= treeSize}; the walk stops at the first ancestor that is not. Sibling hashes are
     * read straight from the store (the untouched sibling subtree at each level), matching the
     * raw-DB-access threat model.
     */
    private void rewriteMaterializedAncestors(long leafIndex, byte[] leafHash, long treeSize) {
        int level = 0;
        long nodeIndex = leafIndex;
        byte[] runningHash = leafHash;
        while (true) {
            int parentLevel = level + 1;
            long parentIndex = nodeIndex >> 1;
            // Exclusive right leaf bound of the parent subtree; if it overruns the tree the parent
            // is an incomplete (ephemeral, never-materialized) node — stop.
            if (((parentIndex + 1) << parentLevel) > treeSize) {
                return;
            }
            byte[] siblingHash = selectNodeHash(level, nodeIndex ^ 1L);
            byte[] parentHash =
                    (nodeIndex & 1L) == 0L
                            ? MerkleHash.hashChildren(runningHash, siblingHash) // running is left
                            : MerkleHash.hashChildren(siblingHash, runningHash); // running is right
            updateNodeHash(parentLevel, parentIndex, parentHash);
            level = parentLevel;
            nodeIndex = parentIndex;
            runningHash = parentHash;
        }
    }

    /**
     * Reads a single materialized node hash. Always an untouched sibling subtree (never a node this
     * tamper has rewritten), so the committed value is the correct one to fold the parent from.
     */
    private byte[] selectNodeHash(int level, long nodeIndex) {
        return nodes.findByLevelAndNodeIndex(level, nodeIndex)
                .orElseThrow(
                        () ->
                                new IllegalStateException(
                                        "missing sibling node ("
                                                + level
                                                + ", "
                                                + nodeIndex
                                                + ") while rewriting the tampered subtree"))
                .getNodeHash();
    }

    /** Overwrites a single materialized node hash in place (the operator's raw-DB mutation). */
    private void updateNodeHash(int level, long nodeIndex, byte[] hash) {
        em.createNativeQuery(
                        "UPDATE tree_nodes SET node_hash = :h WHERE level = :l AND node_index = :i")
                .setParameter("h", hash)
                .setParameter("l", level)
                .setParameter("i", nodeIndex)
                .executeUpdate();
    }

    /**
     * Defense-in-depth: although the {@code @Profile("demo")} annotation already prevents this bean
     * from existing outside the demo profile, re-verify at the call site that {@code demo} is in
     * the active profiles before performing the destructive native UPDATE. If a profile
     * misconfiguration (or a manual instantiation) ever placed this bean in a production context,
     * refuse to mutate the log rather than corrupt a real, signed history.
     */
    private void assertDemoProfileActive() {
        if (!Arrays.asList(environment.getActiveProfiles()).contains(DEMO_PROFILE)) {
            throw new IllegalStateException(
                    "DemoTamperService invoked without the '"
                            + DEMO_PROFILE
                            + "' profile active — refusing to mutate the log. The tamper demo is a"
                            + " demo-only attack simulation and must never run in production.");
        }
    }

    /** The result of a tamper operation: the leaf and its new (mutated) bytes. */
    public record TamperResult(long leafIndex, byte[] tamperedPayload, byte[] tamperedLeafHash) {}
}
