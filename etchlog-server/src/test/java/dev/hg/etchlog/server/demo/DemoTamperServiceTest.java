package dev.hg.etchlog.server.demo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.core.hash.MerkleHash;
import dev.hg.etchlog.core.proof.ConsistencyVerifier;
import dev.hg.etchlog.core.proof.InclusionVerifier;
import dev.hg.etchlog.core.sth.Ed25519SthSigner;
import dev.hg.etchlog.core.sth.SignedTreeHead;
import dev.hg.etchlog.server.log.AppendResult;
import dev.hg.etchlog.server.log.LogService;
import dev.hg.etchlog.server.persistence.entity.LeafEntity;
import dev.hg.etchlog.server.persistence.repository.LeafRepository;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Proves the demo tamper actually produces a <em>detectable</em> mutation: after rewriting a stored
 * leaf, the standalone verifier (the same algorithm the browser runs) rejects both the inclusion
 * proof and the consistency proof against the original signed roots. This is the security claim of
 * the whole tamper demo — if a tamper went undetected it would be a false transparency guarantee.
 *
 * <p>Runs against a real embedded SQLite database with the {@code demo} profile active so the
 * {@code @Profile("demo")} {@link DemoTamperService} bean loads.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
@ActiveProfiles("demo")
@Import({LogService.class, DemoTamperService.class, DemoTamperServiceTest.SigningTestConfig.class})
class DemoTamperServiceTest {

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
        Clock clock() {
            return Clock.systemUTC();
        }
    }

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-tamper.db"));
    }

    @Autowired LogService log;
    @Autowired DemoTamperService tamper;
    @Autowired LeafRepository leaves;
    @Autowired TestEntityManager em;

    @Test
    void tamperBreaksInclusionAndConsistencyAgainstTheSignedRoots() {
        // Append 7 records, capturing the STHs at size 3 (the prefix we'll pin) and size 7.
        List<AppendResult> appends = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            appends.add(log.append(("rec-" + i).getBytes()));
        }
        SignedTreeHead pinned = appends.get(2).sth(); // size 3
        SignedTreeHead current = appends.get(6).sth(); // size 7
        assertThat(pinned.treeSize()).isEqualTo(3L);
        assertThat(current.treeSize()).isEqualTo(7L);

        long target = 1; // < 3, so it lies inside both the pinned prefix and the current tree
        byte[] originalLeafHash = MerkleHash.hashLeaf("rec-1".getBytes());

        // BEFORE tamper: both proofs verify against the signed roots.
        assertThat(
                        InclusionVerifier.verify(
                                originalLeafHash,
                                target,
                                7,
                                log.inclusionAuditPath(target, 7),
                                current.rootHash()))
                .isTrue();
        assertThat(
                        ConsistencyVerifier.verify(
                                3,
                                7,
                                pinned.rootHash(),
                                current.rootHash(),
                                log.consistencyProofNodes(3, 7)))
                .isTrue();

        // Operator silently rewrites the stored leaf.
        DemoTamperService.TamperResult result = tamper.tamper(target);
        // The native UPDATEs bypass the persistence context; drop stale cached entities/nodes.
        em.clear();

        // The stored record really changed, to the reported new value.
        LeafEntity tampered = leaves.findById(target).orElseThrow();
        byte[] tamperedHash = MerkleHash.hashLeaf(tampered.getPayload());
        assertThat(tamperedHash).isEqualTo(result.tamperedLeafHash());
        assertThat(tamperedHash).isNotEqualTo(originalLeafHash);

        // AFTER tamper: the browser recomputes the leaf hash from the bytes it was handed and the
        // root no longer matches the (still validly-signed) STH — inclusion is REJECTED.
        assertThat(
                        InclusionVerifier.verify(
                                tamperedHash,
                                target,
                                7,
                                log.inclusionAuditPath(target, 7),
                                current.rootHash()))
                .isFalse();

        // And a consistency proof re-derived from the tampered level-0 node can no longer reproduce
        // the previously-signed roots — consistency is REJECTED (the tamper alarm).
        assertThat(
                        ConsistencyVerifier.verify(
                                3,
                                7,
                                pinned.rootHash(),
                                current.rootHash(),
                                log.consistencyProofNodes(3, 7)))
                .isFalse();
    }

    @Test
    void tamperingAMissingLeafIsRejected() {
        log.append("only".getBytes());
        em.clear();
        assertThatThrownBy(() -> tamper.tamper(999)).isInstanceOf(DemoLeafNotFoundException.class);
    }
}
