package dev.hg.etchlog.server.log;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.core.sth.Ed25519SthSigner;
import dev.hg.etchlog.core.sth.SignedTreeHead;
import dev.hg.etchlog.core.sth.SthVerifier;
import dev.hg.etchlog.core.tree.MerkleTreeHash;
import dev.hg.etchlog.server.persistence.repository.LeafRepository;
import dev.hg.etchlog.server.persistence.repository.SignedTreeHeadRepository;
import dev.hg.etchlog.server.persistence.repository.TreeNodeRepository;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * End-to-end smoke test for {@link LogService} against a real embedded <strong>SQLite</strong>
 * database with the real JPA repositories, Flyway schema, and transaction manager — confirming the
 * append path wires correctly to persistence (the pure-Java {@link LogServiceAppendPropertyTest}
 * proves the cryptographic invariants exhaustively).
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
@Import({LogService.class, LogServiceIntegrationTest.SigningTestConfig.class})
class LogServiceIntegrationTest {

    @TestConfiguration
    static class SigningTestConfig {
        private final KeyPair keyPair = newKeyPair();

        private static KeyPair newKeyPair() {
            try {
                return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Bean
        Ed25519SthSigner sthSigner() {
            return new Ed25519SthSigner(keyPair.getPrivate());
        }

        @Bean
        PublicKey logPublicKey() {
            return keyPair.getPublic();
        }

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }
    }

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url", () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-log.db"));
    }

    @Autowired LogService logService;
    @Autowired LeafRepository leaves;
    @Autowired TreeNodeRepository nodes;
    @Autowired SignedTreeHeadRepository sths;
    @Autowired PublicKey logPublicKey;

    @Test
    void appendsSequenceAndCommitsVerifiableHeads() {
        List<byte[]> leafHashes = new ArrayList<>();
        AppendResult last = null;
        for (int i = 0; i < 6; i++) {
            last = logService.append(("entry-" + i).getBytes());
            assertThat(last.leafIndex()).isEqualTo((long) i);

            SignedTreeHead sth = last.sth();
            leafHashes.add(dev.hg.etchlog.core.hash.MerkleHash.hashLeaf(("entry-" + i).getBytes()));
            assertThat(sth.rootHash()).isEqualTo(MerkleTreeHash.mth(leafHashes));
            assertThat(SthVerifier.verify(logPublicKey, sth)).isTrue();
        }

        assertThat(leaves.count()).isEqualTo(6);
        assertThat(nodes.findByLevelOrderByNodeIndexAsc(0)).hasSize(6);
        assertThat(sths.findFirstByOrderByTreeSizeDesc().orElseThrow().getTreeSize()).isEqualTo(6L);
        assertThat(last.sth().treeSize()).isEqualTo(6L);
    }

    @Test
    void rejectsDuplicateLeaf() {
        logService.append("dup".getBytes());
        assertThatThrownBy(() -> logService.append("dup".getBytes()))
                .isInstanceOf(DuplicateLeafException.class);
    }
}
