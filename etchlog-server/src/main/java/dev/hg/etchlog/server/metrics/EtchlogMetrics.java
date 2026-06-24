package dev.hg.etchlog.server.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.springframework.stereotype.Component;

/**
 * Micrometer instrumentation for the transparency log's write and read paths, exposed via the
 * Prometheus scrape endpoint (see {@code docs/operations/MONITORING_LOGGING.md}).
 *
 * <p>This is <em>operational</em> observability data — mutable telemetry about service health. It is
 * deliberately confined to {@code etchlog-server}: the crypto core ({@code etchlog-core}) carries
 * zero Micrometer/Spring dependencies (enforced by ArchUnit), so core calls are wrapped with timers
 * here rather than instrumented in place. Metrics never participate in the integrity guarantee — that
 * comes solely from the Merkle tree and Ed25519-signed tree heads, never from these counters.
 *
 * <p>The three headline domain metrics are <strong>append latency</strong> (write-path SLI),
 * <strong>current tree size</strong>, and <strong>proof-generation time</strong> (read-path SLI).
 * Each renders into Prometheus with dots becoming underscores and the base unit appended, e.g.
 * {@code etchlog.append.latency} → {@code etchlog_append_latency_seconds}.
 *
 * @see <a href="../../../../../../../../docs/operations/MONITORING_LOGGING.md">MONITORING_LOGGING.md</a>
 */
@Component
public class EtchlogMetrics {

    /** Allowed values for the {@code result} tag, so cardinality stays bounded. */
    private static final String RESULT_SUCCESS = "success";

    private static final String RESULT_ERROR = "error";

    private final MeterRegistry registry;

    private final Timer appendLatency;
    private final Counter appendSuccess;
    private final Counter appendError;

    private final Timer inclusionProofTimer;
    private final Timer consistencyProofTimer;
    private final Counter inclusionProofSuccess;
    private final Counter inclusionProofError;
    private final Counter consistencyProofSuccess;
    private final Counter consistencyProofError;

    private final Timer sthSignTimer;

    /** Current tree size (= latest STH {@code tree_size}); monotonically non-decreasing. */
    private final AtomicLong treeSize = new AtomicLong(0);

    /** Epoch-seconds timestamp of the latest STH; staleness signals appends have stopped. */
    private final AtomicLong treeHeadTimestampSeconds = new AtomicLong(0);

    public EtchlogMetrics(MeterRegistry registry) {
        this.registry = registry;

        this.appendLatency =
                Timer.builder("etchlog.append.latency")
                        .description("End-to-end time to accept, sequence, and persist a new STH")
                        .publishPercentiles(0.5, 0.95, 0.99)
                        .register(registry);
        this.appendSuccess = appendCounter(RESULT_SUCCESS);
        this.appendError = appendCounter(RESULT_ERROR);

        this.inclusionProofTimer = proofTimer("inclusion");
        this.consistencyProofTimer = proofTimer("consistency");
        this.inclusionProofSuccess = proofCounter("inclusion", RESULT_SUCCESS);
        this.inclusionProofError = proofCounter("inclusion", RESULT_ERROR);
        this.consistencyProofSuccess = proofCounter("consistency", RESULT_SUCCESS);
        this.consistencyProofError = proofCounter("consistency", RESULT_ERROR);

        this.sthSignTimer =
                Timer.builder("etchlog.sth.sign")
                        .description("Ed25519 STH signing time")
                        .register(registry);

        // No baseUnit here: a base unit would suffix the Prometheus name (etchlog_tree_size_leaves),
        // breaking the documented metric name and the alert PromQL that references etchlog_tree_size.
        Gauge.builder("etchlog.tree.size", treeSize, AtomicLong::doubleValue)
                .description("Current number of leaves committed to the log (latest STH tree_size)")
                .register(registry);
        Gauge.builder(
                        "etchlog.tree.head.timestamp",
                        treeHeadTimestampSeconds,
                        AtomicLong::doubleValue)
                .description("Timestamp of the latest STH; staleness indicates appends have stopped")
                .baseUnit("seconds")
                .register(registry);
    }

    private Counter appendCounter(String result) {
        return Counter.builder("etchlog.append.total")
                .description("Append requests, partitioned by outcome")
                .tag("result", result)
                .register(registry);
    }

    private Timer proofTimer(String proofType) {
        return Timer.builder("etchlog.proof.generation")
                .description("Audit-path / consistency-proof build time")
                .tag("proof_type", proofType)
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(registry);
    }

    private Counter proofCounter(String proofType, String result) {
        return Counter.builder("etchlog.proof.total")
                .description("Proof requests served, partitioned by type and outcome")
                .tag("proof_type", proofType)
                .tag("result", result)
                .register(registry);
    }

    /**
     * Times an append and records its outcome. The supplied operation is the full critical section
     * (lock acquisition through transaction commit); on any exception the {@code result=error}
     * counter is incremented and the exception is rethrown unchanged so the caller's error handling
     * is unaffected.
     */
    public <T> T recordAppend(Supplier<T> append) {
        Timer.Sample sample = Timer.start(registry);
        boolean success = false;
        try {
            T result = append.get();
            success = true;
            return result;
        } finally {
            sample.stop(appendLatency);
            (success ? appendSuccess : appendError).increment();
        }
    }

    /**
     * Times an inclusion-proof generation and records its outcome. Exceptions (e.g. a 400/404 from a
     * bad request) count as {@code error} and are rethrown unchanged.
     */
    public <T> T recordInclusionProof(Supplier<T> proof) {
        return recordProof(inclusionProofTimer, inclusionProofSuccess, inclusionProofError, proof);
    }

    /** Times a consistency-proof generation and records its outcome. */
    public <T> T recordConsistencyProof(Supplier<T> proof) {
        return recordProof(
                consistencyProofTimer, consistencyProofSuccess, consistencyProofError, proof);
    }

    private <T> T recordProof(Timer timer, Counter success, Counter error, Supplier<T> proof) {
        Timer.Sample sample = Timer.start(registry);
        boolean ok = false;
        try {
            T result = proof.get();
            ok = true;
            return result;
        } finally {
            sample.stop(timer);
            (ok ? success : error).increment();
        }
    }

    /** Times the Ed25519 signing of a new tree head. */
    public <T> T recordSthSign(Supplier<T> sign) {
        return sthSignTimer.record(sign);
    }

    /**
     * Publishes the latest committed head to the gauges. Call after a successful append once the new
     * STH is persisted, and once at startup to reflect the head already in the store.
     *
     * @param size the latest STH tree size (number of committed leaves)
     * @param timestampMillis the latest STH timestamp in epoch milliseconds
     */
    public void recordHead(long size, long timestampMillis) {
        treeSize.set(size);
        // The gauge is published in seconds (etchlog_tree_head_timestamp_seconds); the STH timestamp
        // is signed and stored in milliseconds, so convert here at the observability boundary.
        treeHeadTimestampSeconds.set(Math.floorDiv(timestampMillis, 1000L));
    }

    /** Reason values are normalized with {@link Locale#ROOT} so the tag is locale-stable. */
    public void recordSthSignError(String reason) {
        Counter.builder("etchlog.sth.sign.errors")
                .description("STH signing failures; any non-zero value is a critical incident")
                .tag("reason", reason == null ? "unknown" : reason.toLowerCase(Locale.ROOT))
                .register(registry)
                .increment();
    }
}
