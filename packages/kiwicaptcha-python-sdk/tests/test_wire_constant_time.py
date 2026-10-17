"""The constant-time comparison behind the signature and rsw checks.

The test measures the minimum per-call time over many rounds for a
mismatch at the first byte and at the last byte of an 8 KiB value,
with a same-input run as the noise floor. A deliberately leaking
early-exit comparator calibrates the measurement: the leaked position
difference must be clearly visible, while the production comparison
must stay inside the noise band.
"""

from __future__ import annotations

import hmac
import time
import unittest

LENGTH = 8192
ROUNDS = 25
CALLS = 20


def measure(compare, a: bytes, b: bytes) -> float:
    best = float("inf")
    for _ in range(ROUNDS):
        start = time.perf_counter_ns()
        for _ in range(CALLS):
            compare(a, b)
        best = min(best, (time.perf_counter_ns() - start) / CALLS)
    return best


def leaking(a: bytes, b: bytes) -> bool:
    for index in range(len(a)):
        if a[index] != b[index]:
            return False
    return True


class WireConstantTimeTest(unittest.TestCase):
    def test_the_secret_comparison_does_not_leak_the_mismatch_position(self) -> None:
        first = b"a" * LENGTH
        head = b"b" + first[1:]
        last = first[:-1] + b"b"

        noise_a = measure(leaking, first, first)
        noise_b = measure(leaking, first, first)
        noise = max(1.0, abs(noise_a - noise_b))

        leak_first = measure(leaking, first, head)
        leak_last = measure(leaking, first, last)
        leak_delta = abs(leak_last - leak_first)
        self.assertGreater(
            leak_delta,
            max(noise * 10, 1_000),
            "the measurement must see an early exit",
        )

        real_first = measure(hmac.compare_digest, first, head)
        real_last = measure(hmac.compare_digest, first, last)
        real_delta = abs(real_last - real_first)
        budget = max(noise * 10, real_first * 0.20, 2_000)
        self.assertLessEqual(
            real_delta,
            budget,
            f"compare_digest leaked the mismatch position: "
            f"first={real_first:.0f}ns last={real_last:.0f}ns noise={noise:.0f}ns",
        )


if __name__ == "__main__":
    unittest.main()
