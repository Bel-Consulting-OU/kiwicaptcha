# frozen_string_literal: true

require_relative 'helper'

# The constant-time comparison behind the signature and rsw checks,
# measured against an early-exit comparator that calibrates the noise
# floor. A position-dependent timing difference on the production
# comparator fails the test.
class WireConstantTimeTest < Minitest::Test
  LENGTH = 8192
  ROUNDS = 25
  CALLS = 20

  def self.measure(compare, a, b)
    best = Float::INFINITY
    ROUNDS.times do
      start = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      CALLS.times { compare.call(a, b) }
      best = [best, (Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - start).to_f / CALLS].min
    end
    best
  end

  def self.leaking(a, b)
    a.bytesize.times do |index|
      return false if a.getbyte(index) != b.getbyte(index)
    end
    true
  end

  def test_the_secret_comparison_does_not_leak_the_mismatch_position
    first = 'a' * LENGTH
    head = "b#{first[1..]}"
    last = "#{first[0...-1]}b"

    noise_a = self.class.measure(self.class.method(:leaking), first, first)
    noise_b = self.class.measure(self.class.method(:leaking), first, first)
    noise = [1.0, (noise_a - noise_b).abs].max

    leak_first = self.class.measure(self.class.method(:leaking), first, head)
    leak_last = self.class.measure(self.class.method(:leaking), first, last)
    leak_delta = (leak_last - leak_first).abs
    assert_operator leak_delta, :>, [noise * 10, 1_000].max,
                    'the measurement must see an early exit'

    real = KiwiCaptcha::Mac.method(:timing_safe_equals)
    real_first = self.class.measure(real, first, head)
    real_last = self.class.measure(real, first, last)
    real_delta = (real_last - real_first).abs
    budget = [[noise * 10, real_first * 0.20].max, 2_000].max
    assert_operator real_delta, :<=, budget,
                    "timing_safe_equals leaked the mismatch position: " \
                    "first=#{real_first.round}ns last=#{real_last.round}ns noise=#{noise.round}ns"
  end
end
