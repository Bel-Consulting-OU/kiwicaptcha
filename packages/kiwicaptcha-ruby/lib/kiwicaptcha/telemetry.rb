# frozen_string_literal: true

module KiwiCaptcha
  # The opt-in telemetry bot-signal gate, mirroring the PHP score and
  # the Rust arithmetic exactly. Three bot classes, deliberately
  # conservative: webdriver, a solve beyond 300 seconds, and uniform
  # discrete event intervals (perfect coefficient of variation).
  module Telemetry
    MAX_HUMAN_DURATION_MS = 300_000
    MIN_DIFFS = 23
    MIN_MEAN = 8.0
    MAX_CV = 0.02

    class << self
      # True when the telemetry carries a bot signal. The duration is
      # clamped at zero for parity even though the token decoder only
      # accepts canonical digit strings.
      def bot_signal?(telemetry, duration_ms)
        return true if telemetry['wd'] == true

        duration = duration_ms.negative? ? 0 : duration_ms
        return true if duration > MAX_HUMAN_DURATION_MS

        events = telemetry['et']
        return false unless events.is_a?(Array)

        diffs = []
        (1...events.length).each do |i|
          t1 = events[i]
          t0 = events[i - 1]
          # Only non-negative integers count; floats, strings and
          # negatives break the pair chain exactly as the strict
          # unsigned coercion would.
          if integer?(t1) && integer?(t0) && t1 >= 0 && t0 >= 0 && t1 >= t0
            diffs << t1 - t0
          end
        end
        return false if diffs.length < MIN_DIFFS

        sum = diffs.sum
        mean = sum.to_f / diffs.length
        return false if mean < MIN_MEAN

        variance = diffs.sum { |d| (d - mean) * (d - mean) } / diffs.length
        cv = Math.sqrt(variance) / mean
        cv < MAX_CV
      end

      private

      def integer?(value)
        value.is_a?(Integer)
      end
    end
  end
end
