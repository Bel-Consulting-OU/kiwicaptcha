defmodule Kiwicaptcha.WireConstantTimeTest do
  use ExUnit.Case, async: false

  # Timing qualification for the constant-time comparison behind the
  # signature and rsw checks. The harness mirrors the Node suite
  # (kiwicaptcha-node/test/wire-constant-time.test.ts): randomized
  # interleaved A/B pairs so machine drift cancels, a robust
  # median-of-paired-deltas statistic, and three comparators per run
  # (positive control, negative control, production). async: false
  # because concurrent suite noise would only widen the MAD.
  #
  # Threshold rule: let d_i be signed paired deltas (arm1 - arm2),
  # med = median(d_i), MAD = median(|d_i - med|). An arm pair is
  # DISTINGUISHABLE iff |med| > 6 * max(MAD, 1ns). A true early-exit
  # effect keeps a consistent sign under random ordering and clears
  # 6xMAD at N = 2000 on any host that can measure at all.
  #
  # Verdicts: an undetectable positive control (or a distinguishable
  # negative control) means the host cannot characterize timing, so the
  # run flunks INCONCLUSIVE — never a PASS and never a leak FAIL of the
  # production comparator. Only a detected control licenses a verdict.

  @length 16_384
  @n 2_000
  @warmup 200
  @k_mad 6

  defp time_once(compare, a, b) do
    start = System.monotonic_time(:nanosecond)
    :erlang.put(:sink, compare.(a, b))
    System.monotonic_time(:nanosecond) - start
  end

  defp median(values) do
    sorted = Enum.sort(values)
    mid = div(length(sorted), 2)

    case rem(length(sorted), 2) do
      1 -> Enum.at(sorted, mid) * 1.0
      0 -> (Enum.at(sorted, mid - 1) + Enum.at(sorted, mid)) / 2
    end
  end

  # Paired A/B measurement with randomized execution order. Arm1 and
  # arm2 run in either order each iteration; the signed delta is always
  # (arm1 - arm2), so a true effect keeps a consistent sign while
  # slow drift hits both arms equally and cancels.
  defp measure_paired(compare, a1, b1, a2, b2, rand_state) do
    for _ <- 1..@warmup do
      time_once(compare, a1, b1)
      time_once(compare, a2, b2)
    end

    {deltas, rand_state} =
      Enum.map_reduce(1..@n, rand_state, fn _, state ->
        # The production comparator allocates two full byte lists per
        # call, so an in-window minor GC would dominate the paired
        # delta. Collect before the pair, untimed; the raised min heap
        # keeps one pair's garbage below the next collection trigger.
        :erlang.garbage_collect()
        {coin, state} = :rand.uniform_s(state)

        {t1, t2} =
          if coin < 0.5 do
            {time_once(compare, a1, b1), time_once(compare, a2, b2)}
          else
            {t2, t1} = {time_once(compare, a2, b2), time_once(compare, a1, b1)}
            {t1, t2}
          end

        {t1 - t2, state}
      end)

    med = median(deltas)
    mad = median(Enum.map(deltas, &abs(&1 - med)))
    threshold = @k_mad * max(mad, 1)

    stats = %{
      median: med,
      mad: mad,
      threshold: threshold,
      distinguishable: abs(med) > threshold
    }

    {stats, rand_state}
  end

  # Deliberately leaky comparator: early exit on first difference.
  defp leaking(a, b), do: leaking(a, b, 0, byte_size(a))

  defp leaking(_a, _b, index, size) when index == size, do: true

  defp leaking(a, b, index, size) do
    if :binary.at(a, index) != :binary.at(b, index) do
      false
    else
      leaking(a, b, index + 1, size)
    end
  end

  defp fmt(name, s) do
    "#{name}: median=#{:erlang.float_to_binary(s.median, decimals: 1)}ns " <>
      "MAD=#{:erlang.float_to_binary(s.mad, decimals: 1)}ns " <>
      "threshold=#{:erlang.float_to_binary(s.threshold, decimals: 1)}ns " <>
      "distinguishable=#{s.distinguishable}"
  end

  test "the secret comparison does not leak the mismatch position" do
    first = String.duplicate("a", @length)
    head = "b" <> binary_part(first, 1, @length - 1)
    last = binary_part(first, 0, @length - 1) <> "b"
    # Fixed seed: A/B randomization is reproducible across runs.
    rand_state = :rand.seed_s(:exsss, {0x5EED1A7E, 0xDEADBEEF, 0x0BADF00D})
    :erlang.process_flag(:min_heap_size, 2_000_000)

    {positive, rand_state} =
      measure_paired(&leaking/2, first, head, first, last, rand_state)

    {negative, rand_state} =
      measure_paired(&leaking/2, first, first, first, first, rand_state)

    {production, _rand_state} =
      measure_paired(&Kiwicaptcha.Mac.timing_safe_equals/2, first, head, first, last, rand_state)

    report =
      Enum.join(
        [
          fmt("positive control (leaky, head vs tail mismatch)", positive),
          fmt("negative control (identical inputs)", negative),
          fmt("production (timing_safe_equals, head vs tail mismatch)", production)
        ],
        "\n"
      )

    # A dead experiment supports no conclusion in either direction:
    # never fail production, never fake a green. The flunk message
    # labels the outcome INCONCLUSIVE so CI can tell it from a leak.
    if not positive.distinguishable or negative.distinguishable do
      flunk(
        "INCONCLUSIVE: this host cannot characterize timing under the #{@k_mad}xMAD rule; " <>
          "production is NOT failed.\n#{report}"
      )
    end

    if production.distinguishable do
      flunk("timing_safe_equals leaked the mismatch position.\n#{report}")
    end

    IO.puts(:stderr, "timing measurement OK:\n#{report}")
    assert :erlang.get(:sink) == false
  end
end
