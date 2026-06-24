package dev.hg.etchlog.server.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.hg.etchlog.server.log.DuplicateLeafException;
import dev.hg.etchlog.server.log.LogService;
import dev.hg.etchlog.server.persistence.repository.LeafRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Verifies the Micrometer instrumentation is wired into the real append and proof-generation paths
 * over the full Spring stack: the three headline metrics (append latency, current tree size,
 * proof-generation time) plus the STH-sign timer and the per-outcome counters all move as records
 * are appended and proofs are served. Asserts <em>deltas</em> against a baseline so the test is
 * robust to a shared {@link MeterRegistry} if the application context is reused across classes.
 *
 * <p>These meters are operational telemetry — they say nothing about the log's integrity, which is
 * established only by the Merkle tree and STH signatures. This test therefore checks plumbing, not
 * cryptographic correctness (that is the job of the property and integration tests).
 */
@SpringBootTest
class EtchlogMetricsTest {

    @TempDir static Path tempDir;

    @DynamicPropertySource
    static void sqliteDatasource(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.datasource.url",
                () -> "jdbc:sqlite:" + tempDir.resolve("etchlog-metrics.db"));
    }

    @Autowired LogService logService;
    @Autowired LeafRepository leaves;
    @Autowired MeterRegistry registry;

    private double appendCount() {
        return registry.get("etchlog.append.latency").timer().count();
    }

    private double appendResult(String result) {
        return registry.get("etchlog.append.total").tag("result", result).counter().count();
    }

    private double proofCount(String proofType) {
        return registry.get("etchlog.proof.generation")
                .tag("proof_type", proofType)
                .timer()
                .count();
    }

    private double sthSignCount() {
        return registry.get("etchlog.sth.sign").timer().count();
    }

    @Test
    void appendAndProofPathsMoveTheMeters() {
        double appendBase = appendCount();
        double successBase = appendResult("success");
        double signBase = sthSignCount();
        double inclusionBase = proofCount("inclusion");
        double consistencyBase = proofCount("consistency");

        for (int i = 0; i < 3; i++) {
            logService.append(("metric-entry-" + i).getBytes());
        }

        // Three appends → three latency observations, three success counts, three STH signings.
        assertThat(appendCount()).isEqualTo(appendBase + 3);
        assertThat(appendResult("success")).isEqualTo(successBase + 3);
        assertThat(sthSignCount()).isEqualTo(signBase + 3);

        // The tree-size gauge reflects the committed leaf count exactly.
        assertThat(registry.get("etchlog.tree.size").gauge().value())
                .isEqualTo((double) leaves.count());

        // The tree-head-timestamp gauge advanced off its initial zero once a head was committed.
        assertThat(registry.get("etchlog.tree.head.timestamp").gauge().value()).isGreaterThan(0d);

        // Serving each proof type records one timed observation.
        logService.inclusionAuditPath(0, leaves.count());
        logService.consistencyProofNodes(1, leaves.count());
        assertThat(proofCount("inclusion")).isEqualTo(inclusionBase + 1);
        assertThat(proofCount("consistency")).isEqualTo(consistencyBase + 1);
    }

    @Test
    void aRejectedAppendCountsAsAnErrorOutcome() {
        logService.append("metric-dup".getBytes());

        double errorBase = appendResult("error");
        double latencyBase = appendCount();

        // A duplicate append is rejected; the failure is still timed and counted as result=error,
        // and the exception propagates unchanged (the metric wrapper never swallows it).
        assertThatThrownBy(() -> logService.append("metric-dup".getBytes()))
                .isInstanceOf(DuplicateLeafException.class);

        assertThat(appendResult("error")).isEqualTo(errorBase + 1);
        assertThat(appendCount()).isEqualTo(latencyBase + 1);
    }
}
