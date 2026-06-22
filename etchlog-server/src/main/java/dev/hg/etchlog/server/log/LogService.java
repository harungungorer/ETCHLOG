package dev.hg.etchlog.server.log;

import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.sth.Ed25519SthSigner;
import dev.hg.etchlog.core.sth.SignedTreeHead;
import dev.hg.etchlog.core.tree.CachedMerkleTree;
import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import dev.hg.etchlog.server.persistence.entity.SignedTreeHeadEntity;
import dev.hg.etchlog.server.persistence.entity.TreeNodeEntity;
import dev.hg.etchlog.server.persistence.repository.LeafRepository;
import dev.hg.etchlog.server.persistence.repository.SignedTreeHeadRepository;
import dev.hg.etchlog.server.persistence.repository.TreeNodeRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The single-sequencer append path — the only mutation Etchlog performs.
 *
 * <p>Each append claims the next monotonically increasing leaf index, persists the leaf and the
 * newly completed left-edge Merkle nodes, recomputes the RFC 6962 tree head, signs it with Ed25519,
 * and stores the resulting Signed Tree Head. The whole operation runs:
 *
 * <ul>
 *   <li>under a process-wide {@link ReentrantLock} so appends are strictly serialized within this
 *       JVM (the single-writer model — see {@code docs/features/MERKLE_LOG_ENGINE.md}), making the
 *       leaf indices a dense, gap-free, strictly increasing sequence; and
 *   <li>inside one transaction so a partial append (leaf without its STH) can never be observed.
 * </ul>
 *
 * <p>Correctness is paramount: the root committed by each STH is computed by {@code etchlog-core}
 * ({@link CachedMerkleTree}, cross-checked against the reference MTH by the core property tests),
 * so the head this service signs is exactly the one every standalone verifier will reconstruct.
 *
 * @see <a
 *     href="../../../../../../../../docs/features/MERKLE_LOG_ENGINE.md">MERKLE_LOG_ENGINE.md</a>
 */
@Service
public class LogService {

    private final LeafRepository leaves;
    private final TreeNodeRepository nodes;
    private final SignedTreeHeadRepository sths;
    private final Ed25519SthSigner signer;
    private final Clock clock;
    private final TransactionTemplate tx;

    /** Serializes appends in-process: the single-writer sequencer. */
    private final ReentrantLock appendLock = new ReentrantLock(true);

    public LogService(
            LeafRepository leaves,
            TreeNodeRepository nodes,
            SignedTreeHeadRepository sths,
            Ed25519SthSigner signer,
            Clock clock,
            PlatformTransactionManager txManager) {
        this.leaves = leaves;
        this.nodes = nodes;
        this.sths = sths;
        this.signer = signer;
        this.clock = clock;
        this.tx = new TransactionTemplate(txManager);
    }

    /**
     * Appends one record. The raw bytes are stored verbatim and hashed with RFC 6962 leaf hashing
     * ({@code SHA-256(0x00 || payload)}); the hash is never recomputed from a re-parsed form.
     *
     * @param payload the exact record bytes the appender submitted (must not be {@code null})
     * @return the assigned leaf index and the STH committing to the log including it
     * @throws DuplicateLeafException if this record's leaf hash is already in the log
     */
    public AppendResult append(byte[] payload) {
        if (payload == null) {
            throw new IllegalArgumentException("payload must not be null");
        }
        byte[] leafHash = MerkleHash.hashLeaf(payload);
        return appendInternal(leafHash, payload.clone());
    }

    private AppendResult appendInternal(byte[] leafHash, byte[] payloadOrNull) {
        appendLock.lock();
        try {
            // The transaction commits before the lock is released, so a concurrent appender always
            // sees the just-committed leaf when it computes the next index.
            return tx.execute(status -> doAppend(leafHash, payloadOrNull));
        } finally {
            appendLock.unlock();
        }
    }

    private AppendResult doAppend(byte[] leafHash, byte[] payloadOrNull) {
        if (leaves.existsByLeafHash(leafHash)) {
            throw new DuplicateLeafException(leafHash);
        }

        long index = leaves.nextLeafIndex(); // == current tree size
        long treeSize = index + 1;

        // Build the ordered leaf-hash list (0..index): the persisted level-0 nodes (0..index-1)
        // plus this new leaf. Read before materializing so we never depend on flush ordering.
        List<TreeNodeEntity> level0 = nodes.findByLevelOrderByNodeIndexAsc(0);
        List<byte[]> leafHashes = new ArrayList<>(level0.size() + 1);
        for (TreeNodeEntity n : level0) {
            leafHashes.add(n.getNodeHash());
        }
        leafHashes.add(leafHash);
        byte[] root = CachedMerkleTree.of(leafHashes).root();

        // Persist the append-only leaf row.
        leaves.save(new LeafEntity(index, leafHash, payloadOrNull));

        // Materialize the newly completed left-edge perfect-subtree nodes (the stable nodes that
        // never change as the tree grows). Ephemeral right-spine nodes are recomputed at proof
        // time.
        materializeCompletedNodes(index, leafHash);

        // Recompute → sign → persist the new head. timestamp(ms) is signed and stored identically.
        long timestampMs = clock.millis();
        SignedTreeHead sth = signer.signSth(treeSize, timestampMs, root);
        sths.save(
                new SignedTreeHeadEntity(
                        treeSize, root, Instant.ofEpochMilli(timestampMs), sth.signature()));

        return new AppendResult(index, sth);
    }

    /**
     * Stores every perfect-subtree node that this append completes. Appending the leaf at {@code
     * index} always materializes its level-0 node; then, while the running node is a right child
     * (odd index), it combines with its already-persisted left sibling to form the parent — the
     * bottom-up carry that exactly mirrors RFC 6962's left-balanced shape.
     */
    private void materializeCompletedNodes(long index, byte[] leafHash) {
        int level = 0;
        long nodeIndex = index;
        byte[] hash = leafHash;
        nodes.save(new TreeNodeEntity(level, nodeIndex, hash));
        while ((nodeIndex & 1L) == 1L) {
            byte[] left =
                    nodes.findByLevelAndNodeIndex(level, nodeIndex - 1)
                            .orElseThrow(
                                    () ->
                                            new IllegalStateException(
                                                    "missing left sibling at completed subtree"))
                            .getNodeHash();
            hash = MerkleHash.hashChildren(left, hash);
            level += 1;
            nodeIndex >>= 1;
            nodes.save(new TreeNodeEntity(level, nodeIndex, hash));
        }
    }
}
