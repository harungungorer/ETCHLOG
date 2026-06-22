package dev.hg.etchlog.server.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.server.persistence.entity.ApiKeyEntity;
import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import dev.hg.etchlog.server.persistence.entity.SignedTreeHeadEntity;
import dev.hg.etchlog.server.persistence.entity.TreeNodeEntity;
import dev.hg.etchlog.server.persistence.entity.TreeNodeId;
import dev.hg.etchlog.server.persistence.repository.ApiKeyRepository;
import dev.hg.etchlog.server.persistence.repository.LeafRepository;
import dev.hg.etchlog.server.persistence.repository.SignedTreeHeadRepository;
import dev.hg.etchlog.server.persistence.repository.TreeNodeRepository;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Exercises the M2 persistence layer against a real <strong>embedded SQLite</strong> database — the
 * single-binary/demo profile. Validates the JPA entities, the append-only repositories, and that
 * the Flyway {@code db/migration/sqlite} migrations apply cleanly and round-trip every table.
 *
 * <p>Runs without Docker, so it provides real-database coverage in environments where the
 * Testcontainers Postgres IT (see {@code PostgresPersistenceIT}) cannot start.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
class SqlitePersistenceTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        // Isolated per-run SQLite file; the default profile already wires the SQLite dialect +
        // Flyway.
        registry.add(
                "spring.datasource.url", () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-test.db"));
    }

    @Autowired LeafRepository leaves;
    @Autowired TreeNodeRepository nodes;
    @Autowired SignedTreeHeadRepository sths;
    @Autowired ApiKeyRepository apiKeys;

    private static byte[] hash(int seed) {
        byte[] h = new byte[32];
        for (int i = 0; i < 32; i++) {
            h[i] = (byte) (seed + i);
        }
        return h;
    }

    private static byte[] sig() {
        byte[] s = new byte[64];
        for (int i = 0; i < 64; i++) {
            s[i] = (byte) i;
        }
        return s;
    }

    @Test
    void migrationsApplyAndStartEmpty() {
        assertThat(leaves.count()).isZero();
        assertThat(nodes.count()).isZero();
        assertThat(sths.count()).isZero();
        assertThat(apiKeys.count()).isZero();
        assertThat(leaves.nextLeafIndex()).isZero();
    }

    @Test
    void leafRoundTripsByIndexAndByHash() {
        byte[] leafHash = hash(10);
        byte[] payload = "hello".getBytes();
        leaves.save(new LeafEntity(0, leafHash, payload));

        Optional<LeafEntity> byIndex = leaves.findById(0L);
        assertThat(byIndex).isPresent();
        assertThat(byIndex.get().getLeafHash()).isEqualTo(leafHash);
        assertThat(byIndex.get().getPayload()).isEqualTo(payload);
        assertThat(byIndex.get().getPayloadSize()).isEqualTo(payload.length);

        assertThat(leaves.findByLeafHash(leafHash)).isPresent();
        assertThat(leaves.existsByLeafHash(leafHash)).isTrue();
        assertThat(leaves.existsByLeafHash(hash(99))).isFalse();
        assertThat(leaves.nextLeafIndex()).isEqualTo(1L);
    }

    @Test
    void leafSupportsNullPayloadPrivateMode() {
        leaves.save(new LeafEntity(0, hash(20), null));
        LeafEntity stored = leaves.findById(0L).orElseThrow();
        assertThat(stored.getPayload()).isNull();
        assertThat(stored.getPayloadSize()).isZero();
    }

    @Test
    void treeNodesAddressedByLevelAndIndex() {
        nodes.saveAll(
                List.of(
                        new TreeNodeEntity(0, 0, hash(1)),
                        new TreeNodeEntity(0, 1, hash(2)),
                        new TreeNodeEntity(1, 0, hash(3))));

        assertThat(nodes.findById(new TreeNodeId(0, 1))).isPresent();
        assertThat(nodes.findByLevelAndNodeIndex(1, 0)).isPresent();
        assertThat(nodes.findByLevelOrderByNodeIndexAsc(0)).hasSize(2);
        assertThat(nodes.findByLevelOrderByNodeIndexAsc(1)).hasSize(1);
    }

    @Test
    void sthHistoryKeepsEveryHeadAndExposesLatest() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        sths.save(new SignedTreeHeadEntity(1, hash(1), now, sig()));
        sths.save(new SignedTreeHeadEntity(2, hash(2), now.plusSeconds(1), sig()));

        assertThat(sths.count()).isEqualTo(2);
        assertThat(sths.findFirstByOrderByTreeSizeDesc().orElseThrow().getTreeSize()).isEqualTo(2L);
        assertThat(sths.findByTreeSizeIn(List.of(1L, 2L))).hasSize(2);
        assertThat(sths.findById(1L).orElseThrow().getRootHash()).isEqualTo(hash(1));
    }

    @Test
    void apiKeyRoundTripsAndRevokes() {
        ApiKeyEntity key = new ApiKeyEntity(hash(7), "ci-runner");
        apiKeys.save(key);

        ApiKeyEntity active = apiKeys.findByKeyHashAndActiveTrue(hash(7)).orElseThrow();
        assertThat(active.isActive()).isTrue();
        assertThat(active.getLabel()).isEqualTo("ci-runner");

        active.revoke();
        apiKeys.save(active);
        assertThat(apiKeys.findByKeyHashAndActiveTrue(hash(7))).isEmpty();
        assertThat(apiKeys.findByKeyHash(hash(7)).orElseThrow().getRevokedAt()).isNotNull();
    }

    @Test
    void entityConstructorsRejectWrongLengthHashes() {
        assertThatThrownBy(() -> new LeafEntity(0, new byte[31], null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TreeNodeEntity(0, 0, new byte[33]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SignedTreeHeadEntity(0, new byte[16], Instant.now(), sig()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SignedTreeHeadEntity(0, hash(1), Instant.now(), new byte[63]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * Append-only guard at the app layer: the log repositories extend the bare {@code Repository}
     * marker, so no {@code delete}/{@code remove} method is ever exposed. This is the storage-layer
     * integrity property enforced in code (the DB grants are the other half).
     */
    @Test
    void logRepositoriesExposeNoDeleteOrUpdatePath() {
        for (Class<?> repo :
                List.of(
                        LeafRepository.class,
                        TreeNodeRepository.class,
                        SignedTreeHeadRepository.class)) {
            for (Method m : repo.getMethods()) {
                assertThat(m.getName())
                        .as(
                                "%s must not expose a mutation/delete method: %s",
                                repo.getSimpleName(), m.getName())
                        .doesNotStartWith("delete")
                        .doesNotStartWith("remove");
            }
        }
    }
}
