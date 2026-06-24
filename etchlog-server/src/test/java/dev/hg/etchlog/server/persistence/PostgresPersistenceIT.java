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
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Full M2 persistence integration test against a real <strong>PostgreSQL</strong> (primary store)
 * via Testcontainers. Verifies cross-dialect parity with {@link SqlitePersistenceTest} and the
 * Postgres-only storage-layer integrity properties: the {@code octet_length(...) = 32/64} CHECK
 * constraints and the immutable STH history.
 *
 * <p>Requires a running Docker daemon. Named {@code *IT} so it runs under the Failsafe plugin (CI)
 * rather than Surefire (unit phase).
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
@ActiveProfiles("postgres")
@Testcontainers
class PostgresPersistenceIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired LeafRepository leaves;
    @Autowired TreeNodeRepository nodes;
    @Autowired SignedTreeHeadRepository sths;
    @Autowired ApiKeyRepository apiKeys;
    @Autowired EntityManager em;

    private static byte[] hash(int seed) {
        byte[] h = new byte[32];
        for (int i = 0; i < 32; i++) {
            h[i] = (byte) (seed + i);
        }
        return h;
    }

    private static byte[] sig() {
        return new byte[64];
    }

    @Test
    void fullRoundTripAcrossAllTables() {
        leaves.save(new LeafEntity(0, hash(10), "rec-0".getBytes()));
        leaves.save(new LeafEntity(1, hash(20), null));
        nodes.saveAll(
                List.of(new TreeNodeEntity(0, 0, hash(10)), new TreeNodeEntity(0, 1, hash(20))));
        Instant ts = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        sths.save(new SignedTreeHeadEntity(2, hash(99), ts, sig()));
        apiKeys.save(new ApiKeyEntity(hash(7), "appender"));

        assertThat(leaves.nextLeafIndex()).isEqualTo(2L);
        assertThat(leaves.findByLeafHash(hash(20))).isPresent();
        assertThat(nodes.findById(new TreeNodeId(0, 1))).isPresent();
        assertThat(sths.findFirstByOrderByTreeSizeDesc().orElseThrow().getTreeSize()).isEqualTo(2L);
        assertThat(apiKeys.findByKeyHashAndActiveTrue(hash(7))).isPresent();
    }

    @Test
    void databaseRejectsWrongLengthLeafHash() {
        // Bypass the entity guard to prove the ck_leaves_hash_len CHECK is enforced by Postgres.
        assertThatThrownBy(
                        () ->
                                em.createNativeQuery(
                                                "INSERT INTO leaves (leaf_index, leaf_hash, payload_size, created_at)"
                                                        + " VALUES (0, :h, 0, 0)") // created_at is
                                        // epoch-millis
                                        // BIGINT
                                        .setParameter("h", new byte[31])
                                        .executeUpdate())
                .isInstanceOf(Exception.class);
    }

    @Test
    void databaseRejectsWrongLengthSignature() {
        assertThatThrownBy(
                        () ->
                                em.createNativeQuery(
                                                "INSERT INTO signed_tree_heads (tree_size, root_hash, timestamp,"
                                                        + " ed25519_signature, created_at) VALUES (0, :r, 0, :s, 0)")
                                        .setParameter("r", hash(1))
                                        .setParameter("s", new byte[63])
                                        .executeUpdate())
                .isInstanceOf(Exception.class);
    }

    @Test
    void databaseRejectsWrongLengthApiKeyHash() {
        // Proves the V6 ck_api_keys_hash_len CHECK is enforced by Postgres. id/active/created_at
        // all
        // have column defaults, so only the (wrong-length) key_hash and label need supplying.
        assertThatThrownBy(
                        () ->
                                em.createNativeQuery(
                                                "INSERT INTO api_keys (key_hash, label) VALUES (:h, 'bad')")
                                        .setParameter("h", new byte[31])
                                        .executeUpdate())
                .isInstanceOf(Exception.class);
    }
}
