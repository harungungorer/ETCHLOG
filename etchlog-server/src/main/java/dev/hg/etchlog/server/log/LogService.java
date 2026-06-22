package dev.hg.etchlog.server.log;

import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.proof.ConsistencyProof;
import dev.hg.etchlog.core.proof.InclusionProof;
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
import java.util.Optional;
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
     * Looks up a leaf by its zero-based index.
     *
     * @param index the leaf index to retrieve
     * @return the matching {@link LeafEntity}, or {@link Optional#empty()} if absent
     */
    public Optional<LeafEntity> findEntry(long index) {
        return leaves.findById(index);
    }

    /**
     * Looks up a leaf by its RFC 6962 leaf hash.
     *
     * @param leafHash the 32-byte leaf hash to look up
     * @return the matching {@link LeafEntity}, or {@link Optional#empty()} if absent
     */
    public Optional<LeafEntity> findEntryByHash(byte[] leafHash) {
        return leaves.findByLeafHash(leafHash);
    }

    /** The current tree size (number of leaves committed so far). */
    public long currentTreeSize() {
        return leaves.count();
    }

    /**
     * The log's latest Signed Tree Head. For an empty log this synthesizes (and signs, but does not
     * persist) the genesis STH: {@code tree_size = 0} with the RFC 6962 empty-tree hash {@code
     * SHA-256("")}.
     */
    public SignedTreeHead currentSth() {
        Optional<SignedTreeHeadEntity> latest = sths.findFirstByOrderByTreeSizeDesc();
        if (latest.isPresent()) {
            SignedTreeHeadEntity e = latest.get();
            return new SignedTreeHead(
                    e.getTreeSize(),
                    e.getRootHash(),
                    e.getTimestamp().toEpochMilli(),
                    e.getEd25519Signature());
        }
        // Empty log: RFC 6962 MTH({}) = SHA-256("") from the core helper (the same value
        // CachedMerkleTree yields for an empty tree); signed on demand so the genesis STH verifies.
        return signer.signSth(0, clock.millis(), MerkleHash.emptyTreeHash());
    }

    /**
     * Generates the RFC 6962 inclusion (audit) path for {@code leafIndex} in the tree of size
     * {@code treeSize}.
     *
     * @throws IllegalArgumentException (→ 400) if {@code leafIndex < 0}, {@code treeSize <= 0}, or
     *     {@code leafIndex >= treeSize}
     * @throws ProofNotAvailableException (→ 404) if {@code treeSize} exceeds the current log size
     */
    public List<byte[]> inclusionAuditPath(long leafIndex, long treeSize) {
        if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) {
            throw new IllegalArgumentException(
                    "require 0 <= leaf_index < tree_size (got leaf_index="
                            + leafIndex
                            + ", tree_size="
                            + treeSize
                            + ")");
        }
        long size = leaves.count();
        if (treeSize > size) {
            throw new ProofNotAvailableException(
                    "tree_size " + treeSize + " exceeds the current log size " + size);
        }
        return InclusionProof.generate(leafHashesUpTo(treeSize), leafIndex, treeSize);
    }

    /**
     * Generates the RFC 6962 consistency proof between sizes {@code first} and {@code second}. A
     * {@code first} of {@code 0} (the empty prefix) or {@code first == second} needs no nodes and
     * returns an empty proof.
     *
     * @throws IllegalArgumentException (→ 400) if {@code first < 0}, {@code second < 0}, or {@code
     *     first > second}
     * @throws ProofNotAvailableException (→ 404) if {@code second} exceeds the current log size
     */
    public List<byte[]> consistencyProofNodes(long first, long second) {
        if (first < 0 || second < 0 || first > second) {
            throw new IllegalArgumentException(
                    "require 0 <= first <= second (got first="
                            + first
                            + ", second="
                            + second
                            + ")");
        }
        long size = leaves.count();
        if (second > size) {
            throw new ProofNotAvailableException(
                    "second " + second + " exceeds the current log size " + size);
        }
        if (first == 0 || first == second) {
            return List.of();
        }
        return ConsistencyProof.generate(leafHashesUpTo(second), first, second);
    }

    /**
     * Loads leaf hashes for indices {@code [0, n)} from the materialized level-0 nodes, in order.
     * Fetches only the {@code n} rows the proof needs (range scan on the {@code (level,
     * node_index)} index) instead of materializing the entire level, so proofs against a historical
     * {@code tree_size} stay cheap on a large log.
     */
    private List<byte[]> leafHashesUpTo(long n) {
        List<TreeNodeEntity> level0 =
                nodes.findByLevelAndNodeIndexLessThanOrderByNodeIndexAsc(0, n);
        if (level0.size() != n) {
            // Level-0 nodes are materialized 1:1 with leaves, so [0, n) is always dense. A
            // shortfall
            // means the store is inconsistent — fail loudly rather than sign a truncated tree.
            throw new IllegalStateException(
                    "expected " + n + " level-0 nodes for the proof, found " + level0.size());
        }
        List<byte[]> hashes = new ArrayList<>((int) n);
        for (TreeNodeEntity node : level0) {
            hashes.add(node.getNodeHash());
        }
        return hashes;
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
