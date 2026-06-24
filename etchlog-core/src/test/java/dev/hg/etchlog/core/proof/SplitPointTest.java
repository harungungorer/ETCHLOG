package dev.hg.etchlog.core.proof;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Guards the RFC 6962 split point {@code k = largest power of two strictly less than n} against
 * 32-bit integer-width regressions.
 *
 * <p>The audit flagged that tree sizes beyond {@code 2^31} cannot be exercised by the shared parity
 * vectors (you cannot materialize four billion leaves). The risk those vectors miss is purely
 * arithmetic: an implementation that computed the split with {@code int} math would silently
 * corrupt the left/right-subtree decision once {@code n} crossed {@code 2^31}. {@link
 * InclusionProof#largestPowerOfTwoLessThan(long)} and {@link
 * ConsistencyProof#largestPowerOfTwoLessThan(long)} both use {@code long} arithmetic ({@code
 * Long.highestOneBit(n - 1)}); these assertions pin that they stay correct across the 2^31 / 2^32 /
 * 2^52 boundaries, so a future refactor to {@code int} would fail loudly here.
 */
class SplitPointTest {

    @Test
    void inclusionSplitPointIsLongCleanAcrossPowerOfTwoBoundaries() {
        assertSplitPoints(InclusionProof::largestPowerOfTwoLessThan);
    }

    @Test
    void consistencySplitPointIsLongCleanAcrossPowerOfTwoBoundaries() {
        assertSplitPoints(ConsistencyProof::largestPowerOfTwoLessThan);
    }

    @Test
    void bothImplementationsAgreeOnEverySplitPoint() {
        for (long n : sampleSizes()) {
            assertThat(InclusionProof.largestPowerOfTwoLessThan(n))
                    .as("inclusion vs consistency split point disagree at n=%d", n)
                    .isEqualTo(ConsistencyProof.largestPowerOfTwoLessThan(n));
        }
    }

    private interface SplitPoint {
        long of(long n);
    }

    private static void assertSplitPoints(SplitPoint f) {
        // Small exact cases (the spec's "strictly less than": for a power of two, k is the next one
        // down — never n itself).
        assertThat(f.of(2)).isEqualTo(1);
        assertThat(f.of(3)).isEqualTo(2);
        assertThat(f.of(4)).isEqualTo(2);
        assertThat(f.of(5)).isEqualTo(4);
        assertThat(f.of(8)).isEqualTo(4);
        assertThat(f.of(9)).isEqualTo(8);

        // Boundaries an int implementation would corrupt.
        long p31 = 1L << 31; // 2,147,483,648 — overflows a signed int
        long p32 = 1L << 32;
        long p52 = 1L << 52; // still exact in IEEE-754 double, the JS number ceiling

        assertThat(f.of(p31)).isEqualTo(1L << 30);
        assertThat(f.of(p31 + 1)).isEqualTo(p31);
        assertThat(f.of(p32)).isEqualTo(1L << 31);
        assertThat(f.of(p32 + 1)).isEqualTo(p32);
        assertThat(f.of(p52)).isEqualTo(1L << 51);
        assertThat(f.of(p52 + 1)).isEqualTo(p52);
    }

    private static long[] sampleSizes() {
        return new long[] {
            2,
            3,
            4,
            5,
            7,
            8,
            9,
            15,
            16,
            17,
            31,
            32,
            33,
            (1L << 30) + 1,
            1L << 31,
            (1L << 31) + 1,
            1L << 32,
            (1L << 32) + 1,
            1L << 52
        };
    }
}
