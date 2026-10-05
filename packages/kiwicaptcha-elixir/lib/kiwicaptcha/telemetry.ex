defmodule Kiwicaptcha.Telemetry do
  @moduledoc """
  The opt-in telemetry bot-signal gate, mirroring the PHP score and
  the Rust arithmetic exactly. Three bot classes, deliberately
  conservative: webdriver, a solve beyond 300 seconds, and uniform
  discrete event intervals (perfect coefficient of variation).
  """

  @max_human_duration_ms 300_000
  @min_diffs 23
  @min_mean 8.0
  @max_cv 0.02

  @doc """
  True when the telemetry carries a bot signal. The duration is
  clamped at zero for parity even though the token decoder only
  accepts canonical digit strings.
  """
  @spec bot_signal?(map(), integer()) :: boolean()
  def bot_signal?(telemetry, duration_ms) when is_map(telemetry) do
    cond do
      telemetry["wd"] == true ->
        true

      max(duration_ms, 0) > @max_human_duration_ms ->
        true

      true ->
        uniform_intervals?(telemetry["et"])
    end
  end

  defp uniform_intervals?(events) when is_list(events) do
    diffs =
      events
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.flat_map(fn [t0, t1] ->
        if integer?(t0) and integer?(t1) and t0 >= 0 and t1 >= t0,
          do: [t1 - t0],
          else: []
      end)

    if length(diffs) < @min_diffs do
      false
    else
      mean = Enum.sum(diffs) / length(diffs)

      if mean < @min_mean do
        false
      else
        variance = Enum.sum(Enum.map(diffs, fn d -> (d - mean) * (d - mean) end)) / length(diffs)
        cv = :math.sqrt(variance) / mean
        cv < @max_cv
      end
    end
  end

  defp uniform_intervals?(_), do: false

  # Only non-negative integers count; floats and negatives break the
  # pair chain exactly as the strict unsigned coercion would.
  defp integer?(value) when is_integer(value), do: true
  defp integer?(_), do: false
end
