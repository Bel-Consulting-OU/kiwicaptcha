package com.kiwicaptcha;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The constant-time comparison behind the signature and rsw checks.
 *
 * Canonical::constantTimeEquals is the production entry point (it wraps
 * MessageDigest.isEqual, the byte[] overload being the primitive), so
 * that wrapper is what is measured here.
 *
 * Methodology. This replaced a minimum-of-rounds design whose noise
 * floor came from two independent best-of runs and whose leaking
 * positive control, when the harness failed to see it, turned red
 * instead of inconclusive. Such a run supports no security conclusion
 * in either direction.
 *
 *   1. Positive control. A byte-by-byte early-return comparator on
 *      8 KiB probes is measured in the same interleaved rounds as the
 *      production probes. Before any production conclusion, the harness
 *      must see the control's first-byte vs last-byte mismatch delta
 *      above a wide margin: a scale-free floor (a fraction of the
 *      control's own full-compare time, so the JIT's speed at the loop
 *      cannot shrink the requirement away), a MAD multiple of the
 *      control's own noise, and sign agreement from a trimmed mean.
 *      If the control is not detected, the whole timing assertion is
 *      inconclusive and the run is skipped with that reason
 *      (Assumptions.assumeTrue). The run refuses a false green: a
 *      passing production assertion without a working control proves
 *      nothing. It refuses a false red just as firmly: a single noisy
 *      measurement is not evidence of a leak.
 *
 *   2. Amplification. 51 rounds of 40 calls per probe on an 8 KiB
 *      value, bounded by construction: the whole file stays in the low
 *      single-digit seconds even on a loaded shared runner.
 *
 *   3. Noise-tolerant estimators. Per-round per-call means (never
 *      minima) are reduced with a median, cross-checked by a 20%
 *      trimmed mean. First-byte-mismatch, last-byte-mismatch and equal
 *      probes are interleaved in a per-round shuffled order driven by a
 *      fixed seed, so the order randomization is real but the run is
 *      reproducible. Production conclusions use paired per-round
 *      differences (last-byte round minus first-byte round of the same
 *      round), which cancel runner-wide drift (CPU frequency scaling,
 *      noisy neighbours, collector phases).
 *
 *   4. The assertion. The production comparator must show no
 *      position-dependent delta beyond a noise-derived budget. The
 *      budget is the larger of an absolute floor, a noise term (a
 *      sigma multiple of the paired differences, capped at a fraction
 *      of a full compare so runner noise cannot mask a full-length
 *      leak), and a fixed fraction of a full compare. A comparator
 *      that short-circuits at the last byte leaks roughly one full
 *      compare time and exceeds this budget by a wide factor.
 */
final class WireConstantTimeTest {
    /** Probe length in bytes (a multiple of the 16-byte hex pattern). */
    private static final int LENGTH = 8192;

    /** Odd, so the median has an unambiguous middle element. */
    private static final int ROUNDS = 51;

    private static final int CALLS = 40;

    /** Untimed calls per (comparator, probe) path before any timed round. */
    private static final int WARMUP_CALLS = 3000;

    /** Fixed seed: the interleaving is real but reproducible. */
    private static final long SEED = 0x4B697743L;

    /** The control delta must clear at least this many MADs of its own noise. */
    private static final double CONTROL_SIGMA = 10.0;

    /** ...and at least this fraction of the control's full-compare time. */
    private static final double CONTROL_MIN_FRACTION = 0.25;

    /** Absolute budget floor (ns) for the production assertion. */
    private static final double PROD_MIN_BUDGET_NS = 250.0;

    /** MADs of paired production differences allowed into the budget... */
    private static final double PROD_SIGMA = 12.0;

    /** ...but never more than this fraction of a full compare. */
    private static final double PROD_MAD_CAP_FRACTION = 0.15;

    /** The budget is at most this fraction of a full compare time. */
    private static final double PROD_FRACTION = 0.25;

    @Test
    void theSecretComparisonDoesNotLeakTheMismatchPosition() {
        byte[] base = hexProbe(LENGTH);
        byte[] first = base.clone();
        first[0] ^= 0x01;
        byte[] last = base.clone();
        last[LENGTH - 1] ^= 0x01;

        // Functional sanity first: both comparators must actually
        // compare (we are timing the right calls, not fast no-ops).
        assertTrue(leaking(base, base));
        assertFalse(leaking(base, first));
        assertFalse(leaking(base, last));
        assertTrue(Canonical.constantTimeEquals(base, base));
        assertFalse(Canonical.constantTimeEquals(base, first));
        assertFalse(Canonical.constantTimeEquals(base, last));

        Map<String, double[]> samples = runInterleavedRounds(base, first, last);

        // Positive control: paired per-round differences of the leaking
        // comparator (last-byte minus first-byte mismatch).
        double[] controlDiff = pairedDifferences(samples, "control");
        double controlDelta = median(controlDiff);
        double controlSpread = medianAbsoluteDeviation(controlDiff);
        double controlTrimmed = trimmedMean(controlDiff);
        double controlEqual = median(samples.get("control.equal"));
        double controlRequired =
                Math.max(CONTROL_MIN_FRACTION * controlEqual, CONTROL_SIGMA * controlSpread);
        Assumptions.assumeTrue(
                controlDelta >= controlRequired && controlTrimmed > 0,
                () -> String.format(
                        "inconclusive: the timing harness cannot see its own leaking"
                                + " positive control on this runner (control delta"
                                + " median=%.0fns trimmed=%.0fns required>=%.0fns"
                                + " [mad=%.0fns, full compare=%.0fns]), so no conclusion"
                                + " about Canonical.constantTimeEquals is supportable"
                                + " in either direction",
                        controlDelta, controlTrimmed, controlRequired, controlSpread, controlEqual));

        // Production: the same paired-difference reduction. Under the
        // null (full-length compare) the median difference sits at
        // jitter scale; a last-byte short-circuit would show almost a
        // full compare time.
        double[] prodDiff = pairedDifferences(samples, "production");
        double prodDelta = Math.abs(median(prodDiff));
        double prodTrimmed = Math.abs(trimmedMean(prodDiff));
        double equalLevel = median(samples.get("production.equal"));
        double prodSpread = medianAbsoluteDeviation(prodDiff);
        double noiseTerm = Math.min(PROD_SIGMA * prodSpread, PROD_MAD_CAP_FRACTION * equalLevel);
        double budget = Math.max(PROD_MIN_BUDGET_NS, Math.max(noiseTerm, PROD_FRACTION * equalLevel));
        assertTrue(
                prodDelta <= budget,
                () -> String.format(
                        "Canonical.constantTimeEquals leaked the mismatch position:"
                                + " |median(late-early)|=%.0fns (trimmed=%.0fns) exceeds budget"
                                + " %.0fns [floor=%.0f noise<=%.0f scale=%.0f; equal=%.0fns,"
                                + " mad=%.0fns] — detected while the positive control showed"
                                + " %.0fns",
                        prodDelta, prodTrimmed, budget, PROD_MIN_BUDGET_NS, noiseTerm,
                        PROD_FRACTION * equalLevel, equalLevel, prodSpread, controlDelta));
    }

    /**
     * The leaking byte-by-byte early-return comparator: the known
     * position-dependent timing behavior the harness must be able to
     * see before any production conclusion is allowed.
     */
    private static boolean leaking(byte[] a, byte[] b) {
        for (var i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * A varied ASCII pattern (rather than one repeated byte) so probes
     * look like real signature material to the cache.
     */
    private static byte[] hexProbe(int length) {
        byte[] pattern = "a5f03b6c1e92d748".getBytes(StandardCharsets.US_ASCII);
        byte[] probe = new byte[length];
        for (var i = 0; i < length; i++) {
            probe[i] = pattern[i % pattern.length];
        }
        return probe;
    }

    /**
     * Nanoseconds-per-call samples keyed "comparator.probe"
     * (control|production x first|last|equal), each a ROUNDS-long
     * array. The comparators and probes are interleaved: every round
     * walks all six slots in a fresh shuffled order drawn from the
     * fixed seed, so drift over time lands on both sides of the paired
     * differences instead of piling onto one probe.
     */
    private static Map<String, double[]> runInterleavedRounds(byte[] base, byte[] first, byte[] last) {
        List<String> slots = new ArrayList<>(List.of(
                "control.first", "control.last", "control.equal",
                "production.first", "production.last", "production.equal"));
        Map<String, double[]> samples = new HashMap<>();
        for (String key : slots) {
            samples.put(key, new double[ROUNDS]);
        }

        // Warm every path untimed: first-touch page faults, profile
        // pollution and lazy JIT binds must not land in a timed round.
        // The results accumulate so nothing is dead-code eliminated.
        long sink = 0;
        for (var warm = 0; warm < WARMUP_CALLS; warm++) {
            for (String key : slots) {
                sink ^= compareSlot(key, base, first, last) ? 1 : 0;
            }
        }
        if (sink != 0) {
            throw new IllegalStateException("warmup saw an unexpected comparator result");
        }

        var random = new Random(SEED);
        for (var round = 0; round < ROUNDS; round++) {
            List<String> order = new ArrayList<>(slots);
            Collections.shuffle(order, random);
            for (String key : order) {
                long sinkRound = 0;
                long start = System.nanoTime();
                for (var call = 0; call < CALLS; call++) {
                    sinkRound ^= compareSlot(key, base, first, last) ? 1 : 0;
                }
                long elapsed = System.nanoTime() - start;
                if (sinkRound != 0) {
                    throw new IllegalStateException(
                            "comparator " + key + " returned an unexpected result");
                }
                samples.get(key)[round] = elapsed / (double) CALLS;
            }
        }
        return samples;
    }

    /** Dispatch one timed call so every slot shares the same call shape. */
    private static boolean compareSlot(String key, byte[] base, byte[] first, byte[] last) {
        return switch (key) {
            case "control.first" -> leaking(base, first);
            case "control.last" -> leaking(base, last);
            case "control.equal" -> leaking(base, base);
            case "production.first" -> Canonical.constantTimeEquals(base, first);
            case "production.last" -> Canonical.constantTimeEquals(base, last);
            case "production.equal" -> Canonical.constantTimeEquals(base, base);
            default -> throw new IllegalStateException(key);
        };
    }

    /**
     * Per-round paired differences, last-byte minus first-byte. Pairing
     * within a round cancels runner-wide drift that would otherwise
     * swamp the position signal.
     */
    private static double[] pairedDifferences(Map<String, double[]> samples, String comparator) {
        double[] first = samples.get(comparator + ".first");
        double[] last = samples.get(comparator + ".last");
        double[] diff = new double[ROUNDS];
        Arrays.setAll(diff, round -> last[round] - first[round]);
        return diff;
    }

    private static double median(double[] values) {
        return percentile(values, 0.5);
    }

    private static double medianAbsoluteDeviation(double[] values) {
        double center = median(values);
        double[] deviations = new double[values.length];
        Arrays.setAll(deviations, i -> Math.abs(values[i] - center));
        return median(deviations);
    }

    /**
     * The mean after discarding {@code trim} of the values at each
     * tail: keeps the estimator tolerant of isolated scheduler hiccups
     * while still using the bulk of the samples (unlike the old
     * minimum).
     */
    private static double trimmedMean(double[] values) {
        return trimmedMean(values, 0.2);
    }

    private static double trimmedMean(double[] values, double trim) {
        double[] sorted = values.clone();
        Arrays.sort(sorted);
        var cut = (int) Math.floor(sorted.length * trim);
        int from = cut;
        int to = sorted.length - cut;
        if (to - from <= 0) {
            return median(sorted);
        }
        double sum = 0;
        for (var i = from; i < to; i++) {
            sum += sorted[i];
        }
        return sum / (to - from);
    }

    private static double percentile(double[] values, double p) {
        double[] sorted = values.clone();
        Arrays.sort(sorted);
        if (sorted.length == 0) {
            throw new IllegalArgumentException("percentile of an empty sample");
        }
        double index = (sorted.length - 1) * p;
        int low = (int) Math.floor(index);
        int high = (int) Math.ceil(index);
        if (low == high) {
            return sorted[low];
        }
        return sorted[low] + (sorted[high] - sorted[low]) * (index - low);
    }
}
