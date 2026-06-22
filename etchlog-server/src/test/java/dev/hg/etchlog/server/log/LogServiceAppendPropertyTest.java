package dev.hg.etchlog.server.log;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.proof.InclusionProof;
import dev.hg.etchlog.core.proof.InclusionVerifier;
import dev.hg.etchlog.core.sth.Ed25519SthSigner;
import dev.hg.etchlog.core.sth.SignedTreeHead;
import dev.hg.etchlog.core.sth.SthVerifier;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import dev.hg.etchlog.server.persistence.entity.SignedTreeHeadEntity;
import dev.hg.etchlog.server.persistence.entity.TreeNodeEntity;
import dev.hg.etchlog.server.persistence.entity.TreeNodeId;
import dev.hg.etchlog.server.persistence.repository.LeafRepository;
import dev.hg.etchlog.server.persistence.repository.SignedTreeHeadRepository;
import dev.hg.etchlog.server.persistence.repository.TreeNodeRepository;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

/**
 * Property-based correctness tests for the {@link LogService} append path, run as plain Java
 * against in-memory fake repositories — no Spring, no database. They assert the invariants that
 * make a subtly-wrong append a false security claim:
 *
 * <ul>
 *   <li>leaf indices are dense, gap-free, strictly increasing ({@code 0..N-1});
 *   <li>every signed root equals the reference RFC 6962 MTH over the leaf hashes;
 *   <li>every STH verifies under the log's public key (and fails under a wrong key);
 *   <li>each materialized perfect-subtree node equals the MTH over its leaf range;
 *   <li>an inclusion proof for every leaf verifies against the committed root.
 * </ul>
 *
 * <p>The cryptographic primitives themselves are property-tested in {@code etchlog-core}; this
 * suite proves the server's wiring and node materialization faithfully reuse them.
 */
class LogServiceAppendPropertyTest {

    @Property(tries = 200)
    void appendSequenceUpholdsAllInvariants(@ForAll @IntRange(min = 1, max = 80) int n)
            throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair wrong = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        FakeLeaves leaves = new FakeLeaves();
        FakeNodes nodes = new FakeNodes();
        FakeSths sths = new FakeSths();
        LogService service = newService(leaves, nodes, sths, kp);

        List<byte[]> leafHashes = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            byte[] payload = ("record-" + i).getBytes();
            AppendResult result = service.append(payload);

            // Dense, monotonic indices.
            assertThat(result.leafIndex()).isEqualTo((long) i);
            SignedTreeHead sth = result.sth();
            assertThat(sth.treeSize()).isEqualTo((long) (i + 1));

            // Root == reference MTH over the leaf hashes so far.
            leafHashes.add(MerkleHash.hashLeaf(payload));
            assertThat(sth.rootHash()).isEqualTo(MerkleTreeHash.mth(leafHashes));

            // STH verifies under the real key, not under a different one.
            assertThat(SthVerifier.verify(kp.getPublic(), sth)).isTrue();
            assertThat(SthVerifier.verify(wrong.getPublic(), sth)).isFalse();
        }

        byte[] finalRoot = MerkleTreeHash.mth(leafHashes);

        // Persistence shape: one leaf row and one level-0 node per leaf; one STH per append.
        assertThat(leaves.store).hasSize(n);
        assertThat(nodes.byLevel(0)).hasSize(n);
        assertThat(sths.store).hasSize(n);
        assertThat(sths.findFirstByOrderByTreeSizeDesc().orElseThrow().getTreeSize())
                .isEqualTo((long) n);

        // Every materialized node is exactly the MTH over the leaf range it covers.
        for (Map<Long, TreeNodeEntity> level : nodes.levels.values()) {
            for (TreeNodeEntity node : level.values()) {
                long span = 1L << node.getLevel();
                long lo = node.getNodeIndex() * span;
                long hi = lo + span;
                assertThat(hi).as("only complete subtrees are materialized").isLessThanOrEqualTo(n);
                byte[] expected = MerkleTreeHash.mth(leafHashes.subList((int) lo, (int) hi));
                assertThat(node.getNodeHash())
                        .as("node (%d,%d)", node.getLevel(), node.getNodeIndex())
                        .isEqualTo(expected);
            }
        }

        // Inclusion proof for every leaf verifies against the final committed root.
        for (int i = 0; i < n; i++) {
            List<byte[]> path = InclusionProof.generate(leafHashes, i, n);
            assertThat(InclusionVerifier.verify(leafHashes.get(i), i, n, path, finalRoot))
                    .as("inclusion proof for leaf %d", i)
                    .isTrue();
        }
    }

    @Test
    void duplicateLeafIsRejected() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        LogService service = newService(new FakeLeaves(), new FakeNodes(), new FakeSths(), kp);

        service.append("only-once".getBytes());
        assertThatThrownBy(() -> service.append("only-once".getBytes()))
                .isInstanceOf(DuplicateLeafException.class);
    }

    @Test
    void nullPayloadIsRejected() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        LogService service = newService(new FakeLeaves(), new FakeNodes(), new FakeSths(), kp);
        assertThatThrownBy(() -> service.append(null)).isInstanceOf(IllegalArgumentException.class);
    }

    private static LogService newService(
            FakeLeaves leaves, FakeNodes nodes, FakeSths sths, KeyPair kp) {
        Clock fixed = Clock.fixed(Instant.ofEpochMilli(1_750_000_000_000L), ZoneOffset.UTC);
        return new LogService(
                leaves, nodes, sths, new Ed25519SthSigner(kp.getPrivate()), fixed, new NoOpTxm());
    }

    // ----- in-memory fakes -------------------------------------------------------------------

    /** Runs the callback directly; the append path's own lock provides serialization in tests. */
    private static final class NoOpTxm implements PlatformTransactionManager {
        @Override
        public TransactionStatus getTransaction(TransactionDefinition def) {
            return new SimpleTransactionStatus();
        }

        @Override
        public void commit(TransactionStatus status) {}

        @Override
        public void rollback(TransactionStatus status) {}
    }

    private static final class FakeLeaves implements LeafRepository {
        final TreeMap<Long, LeafEntity> store = new TreeMap<>();

        @Override
        public LeafEntity save(LeafEntity leaf) {
            store.put(leaf.getLeafIndex(), leaf);
            return leaf;
        }

        @Override
        public Optional<LeafEntity> findById(Long leafIndex) {
            return Optional.ofNullable(store.get(leafIndex));
        }

        @Override
        public Optional<LeafEntity> findByLeafHash(byte[] leafHash) {
            return store.values().stream()
                    .filter(l -> Arrays.equals(l.getLeafHash(), leafHash))
                    .findFirst();
        }

        @Override
        public boolean existsByLeafHash(byte[] leafHash) {
            return findByLeafHash(leafHash).isPresent();
        }

        @Override
        public long count() {
            return store.size();
        }

        @Override
        public long nextLeafIndex() {
            return store.isEmpty() ? 0L : store.lastKey() + 1;
        }
    }

    private static final class FakeNodes implements TreeNodeRepository {
        final TreeMap<Integer, TreeMap<Long, TreeNodeEntity>> levels = new TreeMap<>();

        TreeMap<Long, TreeNodeEntity> byLevel(int level) {
            return levels.getOrDefault(level, new TreeMap<>());
        }

        @Override
        public TreeNodeEntity save(TreeNodeEntity node) {
            levels.computeIfAbsent(node.getLevel(), k -> new TreeMap<>())
                    .put(node.getNodeIndex(), node);
            return node;
        }

        @Override
        public <S extends TreeNodeEntity> List<S> saveAll(Iterable<S> nodes) {
            List<S> saved = new ArrayList<>();
            for (S n : nodes) {
                save(n);
                saved.add(n);
            }
            return saved;
        }

        @Override
        public Optional<TreeNodeEntity> findById(TreeNodeId id) {
            return findByLevelAndNodeIndex(id.getLevel(), id.getNodeIndex());
        }

        @Override
        public Optional<TreeNodeEntity> findByLevelAndNodeIndex(int level, long nodeIndex) {
            return Optional.ofNullable(byLevel(level).get(nodeIndex));
        }

        @Override
        public List<TreeNodeEntity> findByLevelOrderByNodeIndexAsc(int level) {
            return new ArrayList<>(byLevel(level).values());
        }

        @Override
        public List<TreeNodeEntity> findByLevelAndNodeIndexLessThanOrderByNodeIndexAsc(
                int level, long nodeIndexExclusive) {
            return new ArrayList<>(byLevel(level).headMap(nodeIndexExclusive).values());
        }

        @Override
        public long count() {
            return levels.values().stream().mapToLong(Map::size).sum();
        }
    }

    private static final class FakeSths implements SignedTreeHeadRepository {
        final TreeMap<Long, SignedTreeHeadEntity> store = new TreeMap<>();

        @Override
        public SignedTreeHeadEntity save(SignedTreeHeadEntity sth) {
            store.put(sth.getTreeSize(), sth);
            return sth;
        }

        @Override
        public Optional<SignedTreeHeadEntity> findById(Long treeSize) {
            return Optional.ofNullable(store.get(treeSize));
        }

        @Override
        public Optional<SignedTreeHeadEntity> findFirstByOrderByTreeSizeDesc() {
            return store.isEmpty() ? Optional.empty() : Optional.of(store.lastEntry().getValue());
        }

        @Override
        public List<SignedTreeHeadEntity> findByTreeSizeIn(Collection<Long> treeSizes) {
            List<SignedTreeHeadEntity> out = new ArrayList<>();
            for (Long s : treeSizes) {
                SignedTreeHeadEntity e = store.get(s);
                if (e != null) {
                    out.add(e);
                }
            }
            return out;
        }

        @Override
        public long count() {
            return store.size();
        }
    }
}
