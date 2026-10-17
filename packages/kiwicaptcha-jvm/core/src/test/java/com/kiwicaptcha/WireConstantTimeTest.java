package com.kiwicaptcha;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.function.BiPredicate;
import org.junit.jupiter.api.Test;

/**
 * The constant-time comparison behind the signature and rsw checks,
 * measured against an early-exit comparator that calibrates the noise
 * floor. A position-dependent timing difference on the production
 * comparator fails the test.
 */
final class WireConstantTimeTest {
    private static final int LENGTH = 8192;
    private static final int ROUNDS = 25;
    private static final int CALLS = 100;

    private static boolean leaking(byte[] a, byte[] b) {
        for (var i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    private interface ByteCompare {
        boolean test(byte[] a, byte[] b);
    }

    private static double measure(ByteCompare compare, byte[] a, byte[] b) {
        for (var i = 0; i < CALLS * 20; i++) {
            compare.test(a, b);
        }
        var best = Double.POSITIVE_INFINITY;
        for (var round = 0; round < ROUNDS; round++) {
            var start = System.nanoTime();
            for (var call = 0; call < CALLS; call++) {
                compare.test(a, b);
            }
            best = Math.min(best, (System.nanoTime() - start) / (double) CALLS);
        }
        return best;
    }

    /** Measure the two positions in the same JIT and GC state, round by round. */
    private static double[] measurePair(ByteCompare compare, byte[] a, byte[] head, byte[] last) {
        for (var i = 0; i < CALLS * 20; i++) {
            compare.test(a, head);
            compare.test(a, last);
        }
        var bestHead = Double.POSITIVE_INFINITY;
        var bestLast = Double.POSITIVE_INFINITY;
        for (var round = 0; round < ROUNDS; round++) {
            var start = System.nanoTime();
            for (var call = 0; call < CALLS; call++) {
                compare.test(a, head);
            }
            bestHead = Math.min(bestHead, (System.nanoTime() - start) / (double) CALLS);

            start = System.nanoTime();
            for (var call = 0; call < CALLS; call++) {
                compare.test(a, last);
            }
            bestLast = Math.min(bestLast, (System.nanoTime() - start) / (double) CALLS);
        }
        return new double[] {bestHead, bestLast};
    }

    @Test
    void theSecretComparisonDoesNotLeakTheMismatchPosition() {
        var first = new byte[LENGTH];
        java.util.Arrays.fill(first, (byte) 'a');
        var head = first.clone();
        head[0] = 'b';
        var last = first.clone();
        last[LENGTH - 1] = 'b';

        var noiseA = measure(WireConstantTimeTest::leaking, first, first);
        var noiseB = measure(WireConstantTimeTest::leaking, first, first);
        var noise = Math.max(1.0, Math.abs(noiseA - noiseB));

        var leakPair = measurePair(WireConstantTimeTest::leaking, first, head, last);
        assertTrue(
                Math.abs(leakPair[1] - leakPair[0]) > Math.max(noise * 10, 1_000),
                "the measurement must see an early exit");

        // The noise floor of the code under test, not of the leaking
        // comparator: identical inputs twice through the same instructions.
        // A full-suite run on a shared machine carries JIT and collector
        // jitter that the early-exit comparator's own path does not see,
        // and measuring it there made this assertion flaky while the
        // detection assertion above still had a fifty-fold margin.
        var selfA = measure(Canonical::constantTimeEquals, first, first);
        var selfB = measure(Canonical::constantTimeEquals, first, first);
        var selfNoise = Math.max(1.0, Math.abs(selfA - selfB));

        var realPair = measurePair(Canonical::constantTimeEquals, first, head, last);
        var realFirst = realPair[0];
        var realLast = realPair[1];
        var realDelta = Math.abs(realLast - realFirst);
        var budget = Math.max(Math.max(Math.max(noise * 10, selfNoise * 10), realFirst * 0.20), 2_000);
        assertTrue(
                realDelta <= budget,
                () -> "constantTimeEquals leaked the mismatch position: first="
                        + realFirst + "ns last=" + realLast + "ns noise=" + noise + "ns");
    }
}
