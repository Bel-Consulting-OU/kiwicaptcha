defmodule Kiwicaptcha.WireHostileCorpusTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The shared hostile wire corpus against the Elixir decoder. The
  # fixture is expanded by the PHP generator and read byte-for-byte by
  # every hosted SDK suite; the expected verdicts are the reference
  # decoder's.
  @corpus protocol("solution-token-v1/wire-hostile-corpus.json")

  @class_map %{
    invalid_base64: "base64",
    invalid_utf8: "utf8",
    invalid_counter: "counter",
    counter_exceeds_solver_maximum: "counter",
    invalid_duration: "duration",
    malformed: "malformed"
  }

  test "the corpus is broad" do
    assert @corpus["counts"]["total"] >= 100
  end

  for row <- @corpus["vectors"] do
    test "wire corpus: #{row["id"]}" do
      row = unquote(Macro.escape(row))
      expected = row["expect"]

      if expected["verdict"] == "accept" do
        {:ok, token} = Kiwicaptcha.Token.decode(row["raw"])
        assert token.counter == expected["counter"], row["id"]
        assert token.duration_ms == expected["duration_ms"], row["id"]
        assert token.execution_digest == expected["execution_digest"], row["id"]
        assert token.execution_trace == expected["execution_trace"], row["id"]
        assert token.rsw_proof == expected["rsw_proof"], row["id"]

        if Map.has_key?(expected, "telemetry") do
          assert token.telemetry == expected["telemetry"], "#{row["id"]}: telemetry value"
        end

        if Map.has_key?(expected, "telemetry_score") do
          assert Kiwicaptcha.Telemetry.bot_signal?(token.telemetry, token.duration_ms) ==
                   expected["telemetry_score"],
                 "#{row["id"]}: telemetry score"
        end
      else
        assert {:error, code} = Kiwicaptcha.Token.decode(row["raw"]),
               "#{row["id"]}: the Elixir decoder accepted a hostile row"

        if expected["class"] != "any" do
          assert @class_map[code] == expected["class"], row["id"]
        end
      end
    end
  end
end
