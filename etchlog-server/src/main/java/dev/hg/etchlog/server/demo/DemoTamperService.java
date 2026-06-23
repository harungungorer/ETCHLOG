package dev.hg.etchlog.server.demo;

import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import dev.hg.etchlog.server.persistence.repository.LeafRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.nio.charset.StandardCharsets;
import org.springframework.context.annotation.Profile;
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
 * <p>It rewrites two rows and leaves the signed tree heads untouched:
 *
 * <ol>
 *   <li>{@code leaves}: the {@code payload} and its RFC 6962 {@code leaf_hash}; and
 *   <li>{@code tree_nodes} at {@code (level 0, node_index = leafIndex)}: the materialized leaf hash
 *       that inclusion/consistency proof generation reads.
 * </ol>
 *
 * <p>Because the {@code signed_tree_heads} rows are NOT re-signed, the published STH still carries
 * a <em>valid Ed25519 signature</em> over the original root. A verifier therefore sees a perfectly
 * signed head whose committed data no longer matches the store: the browser recomputes the leaf
 * hash from the bytes it is handed and the root no longer reconstructs (inclusion fails), and a
 * consistency proof re-derived from the tampered level-0 node can no longer reproduce the
 * previously-signed roots (consistency fails). Tamper-evident, exactly as advertised.
 *
 * <p><strong>Never enable the {@code demo} profile in production.</strong> There is no legitimate
 * edit-a-leaf operation in Etchlog.
 */
@Service
@Profile("demo")
public class DemoTamperService {

    /** Visible marker appended to the record so the tampering is obvious in the UI. */
    static final String TAMPER_MARKER = " ⚠ TAMPERED ⚠";

    private final LeafRepository leaves;

    @PersistenceContext private EntityManager em;

    public DemoTamperService(LeafRepository leaves) {
        this.leaves = leaves;
    }

    /**
     * Mutates the leaf at {@code index} in place. Returns the new (tampered) payload and leaf hash
     * so the caller can show what the operator changed it to.
     *
     * @throws DemoLeafNotFoundException if no leaf exists at {@code index}
     */
    @Transactional
    public TamperResult tamper(long index) {
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

        // Rewrite the materialized level-0 node so proof generation reflects the tampered leaf,
        // while the higher perfect-subtree nodes (and the signed STHs folded from them) keep the
        // original root. That divergence is what the verifier detects.
        em.createNativeQuery(
                        "UPDATE tree_nodes SET node_hash = :h WHERE level = 0 AND node_index = :i")
                .setParameter("h", tamperedHash)
                .setParameter("i", index)
                .executeUpdate();

        return new TamperResult(index, tamperedPayload, tamperedHash);
    }

    /** The result of a tamper operation: the leaf and its new (mutated) bytes. */
    public record TamperResult(long leafIndex, byte[] tamperedPayload, byte[] tamperedLeafHash) {}
}
