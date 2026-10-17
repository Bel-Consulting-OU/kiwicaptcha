defmodule Kiwicaptcha.WireConstantTimeTest do
  use ExUnit.Case, async: true

  # The constant-time comparison behind the signature and rsw checks,
  # measured against an early-exit comparator that calibrates the noise
  # floor. A position-dependent timing difference on the production
  # comparator fails the test.
  @length 8192
  @rounds 25
  @calls 20

  defp measure(compare, a, b) do
    Enum.reduce(1..@rounds, :infinity, fn _, best ->
      start = System.monotonic_time(:nanosecond)

      Enum.each(1..@calls, fn _ -> compare.(a, b) end)

      elapsed = (System.monotonic_time(:nanosecond) - start) / @calls
      if best == :infinity, do: elapsed, else: min(best, elapsed)
    end)
  end

  defp leaking(a, b), do: leaking(a, b, 0, byte_size(a))

  defp leaking(_a, _b, index, size) when index == size, do: true

  defp leaking(a, b, index, size) do
    if :binary.at(a, index) != :binary.at(b, index) do
      false
    else
      leaking(a, b, index + 1, size)
    end
  end

  test "the secret comparison does not leak the mismatch position" do
    first = String.duplicate("a", @length)
    head = "b" <> binary_part(first, 1, @length - 1)
    last = binary_part(first, 0, @length - 1) <> "b"

    noise_a = measure(&leaking/2, first, first)
    noise_b = measure(&leaking/2, first, first)
    noise = max(1.0, abs(noise_a - noise_b))

    leak_first = measure(&leaking/2, first, head)
    leak_last = measure(&leaking/2, first, last)
    leak_delta = abs(leak_last - leak_first)

    assert leak_delta > max(noise * 10, 1_000),
           "the measurement must see an early exit (first=#{leak_first}ns last=#{leak_last}ns noise=#{noise}ns)"

    real_first = measure(&Kiwicaptcha.Mac.timing_safe_equals/2, first, head)
    real_last = measure(&Kiwicaptcha.Mac.timing_safe_equals/2, first, last)
    real_delta = abs(real_last - real_first)
    budget = max(max(noise * 10, real_first * 0.20), 2_000)

    assert real_delta <= budget,
           "timing_safe_equals leaked the mismatch position: first=#{real_first}ns last=#{real_last}ns noise=#{noise}ns"
  end
end
